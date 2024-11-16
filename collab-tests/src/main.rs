use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use bdk::bitcoin::psbt::{PartiallySignedTransaction, Prevouts};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::sighash::{ScriptPath, SighashCache};
use bdk::bitcoin::taproot::Signature;
use bdk::bitcoin::{self, Network, PrivateKey, PublicKey};
use bdk::blockchain::EsploraBlockchain;
use bdk::database::MemoryDatabase;
use bdk::keys::{GeneratableDefaultOptions, GeneratedKey};
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::{miniscript, Descriptor};
use bdk::signer::{SignerContext, SignerOrdering, SignerWrapper};
use bdk::wallet::AddressIndex;
use bdk::{FeeRate, KeychainKind, SignOptions, SyncOptions, Wallet};
use fedimint_core::secp256k1::XOnlyPublicKey;
use fedimint_testing::envs::FM_PORT_ESPLORA_ENV;
use rand::rngs::OsRng;
use schnorr_fun::frost::{self, FrostKey};
use schnorr_fun::fun::marker::{Normal, Public};
use schnorr_fun::fun::{hex, Scalar};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::Message;
use serde_json::Value;
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::bit::{B0, B1};
use sha2::digest::typenum::{UInt, UTerm};
use sha2::{OidSha256, Sha256, Sha256VarCore};
use tracing::info;

pub type Frost = schnorr_fun::frost::Frost<
    CoreWrapper<
        CtVariableCoreWrapper<
            Sha256VarCore,
            UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
            OidSha256,
        >,
    >,
    Synthetic<
        CoreWrapper<
            CtVariableCoreWrapper<
                Sha256VarCore,
                UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                OidSha256,
            >,
        >,
        GlobalRng<OsRng>,
    >,
>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let network = Network::Regtest;
        let secp = Secp256k1::new();

        let internal_key: GeneratedKey<_, miniscript::Tap> = PrivateKey::generate_default()?;
        let internal_key = internal_key.into_key();
        let internal_public_key = PublicKey::from_private_key(&secp, &internal_key);

        let private_key1: GeneratedKey<_, miniscript::Tap> = PrivateKey::generate_default()?;
        let private_key1 = private_key1.into_key();
        let public_key1 = PublicKey::from_private_key(&secp, &private_key1);

        let private_key2: GeneratedKey<_, miniscript::Tap> = PrivateKey::generate_default()?;
        let private_key2 = private_key2.into_key();
        let public_key2 = PublicKey::from_private_key(&secp, &private_key2);

        let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>();
        let (frost_key, shares) = frost_dkg(&frost);
        info!(?shares, "FROST SHARES");
        let frost_public_key = frost_key.public_key().to_bytes();
        let frost_pub_key = PublicKey::from_slice(&frost_public_key).unwrap();

        let keys = [public_key1, public_key2, frost_pub_key];

        let keys_joined: String = keys
            .into_iter()
            .map(|k| format!("pk({})", k))
            .collect::<Vec<_>>()
            .join(",");
        info!("{}", keys_joined);
        let policy_str = format!("thresh({},{})", 2, keys_joined);
        let policy = Concrete::<PublicKey>::from_str(&policy_str)?.compile()?;
        let tap_leaf = TapTree::Leaf(Arc::new(policy));

        let descriptor = Descriptor::new_tr(internal_public_key, Some(tap_leaf))?.to_string();
        info!("{}", descriptor);

        let mut wallet =
            Wallet::new(descriptor.as_str(), None, network, MemoryDatabase::new()).unwrap();

        let address = wallet.get_address(AddressIndex::New).unwrap();
        let bitcoind = dev_fed.bitcoind().await.unwrap();
        bitcoind
            .generate_to_address(101, &address.address)
            .await
            .unwrap();

        // Wait for esplora to be available
        let _esplora = dev_fed.esplora().await.unwrap();
        let port = std::env::var(FM_PORT_ESPLORA_ENV).unwrap();
        let url = format!("http://127.0.0.1:{port}");
        info!(?url, "LDK Esplora URL");
        let esplora = EsploraBlockchain::new(&url, 20);
        wallet.sync(&esplora, SyncOptions::default()).unwrap();

        info!("Wallet Balance: {:#?}", wallet.get_balance().unwrap());

        let wallet_policy = wallet.policies(KeychainKind::External)?.unwrap();
        let mut path = BTreeMap::new();
        path.insert(wallet_policy.id, vec![1]);

        let new_address = bitcoind.get_new_address().await.unwrap();
        let mut tx_builder = wallet.build_tx();
        tx_builder
            .drain_wallet()
            .drain_to(new_address.script_pubkey())
            .fee_rate(FeeRate::from_sat_per_vb(3.0))
            .policy_path(path, KeychainKind::External);
        let (mut psbt, details) = tx_builder.finish().unwrap();

        info!(?details, "TransactionDetails");

        //frost_sign_psbt(&mut psbt, &frost, frost_key, shares);
        sign_psbt(&mut wallet, private_key1, &mut psbt);
        sign_psbt(&mut wallet, private_key2, &mut psbt);

        let tx = psbt.extract_tx();
        let hex_tx = hex::encode(&bitcoin::consensus::encode::serialize(&tx));
        info!(?hex_tx, "HexTx");

        esplora.broadcast(&tx).unwrap();

        // Mine some blocks
        let new_address = bitcoind.get_new_address().await.unwrap();
        bitcoind
            .generate_to_address(50, &new_address)
            .await
            .unwrap();
        wallet.sync(&esplora, SyncOptions::default()).unwrap();
        info!("Wallet Balance: {:#?}", wallet.get_balance().unwrap());

        Ok(())
    })
    .await
}

fn sign_psbt(
    wallet: &mut Wallet<MemoryDatabase>,
    private_key: PrivateKey,
    psbt: &mut PartiallySignedTransaction,
) {
    let signer = SignerWrapper::new(
        private_key,
        SignerContext::Tap {
            is_internal_key: false,
        },
    );
    wallet.add_signer(KeychainKind::External, SignerOrdering(0), Arc::new(signer));
    let finalized = wallet.sign(psbt, SignOptions::default()).unwrap();
    info!(?finalized, "Finalized");
}

fn frost_dkg(frost: &Frost) -> (FrostKey<Normal>, BTreeMap<Scalar<Public>, Scalar>) {
    let shares = frost.simulate_keygen(1, 2, &mut OsRng);
    shares
}

fn frost_sign_psbt(
    psbt: &mut PartiallySignedTransaction,
    frost: &Frost,
    frost_key: FrostKey<Normal>,
    shares: BTreeMap<Scalar<Public>, Scalar>,
) {
    let txouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.as_ref().expect("no witness").clone())
        .collect::<Vec<_>>();
    let prevouts = Prevouts::All(&txouts);
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let xonly_frost_key = frost_key.clone().into_xonly_key();
    let xonly_bytes = frost_key.public_key().to_xonly_bytes();
    let xonly_key = XOnlyPublicKey::from_slice(&xonly_bytes).unwrap();
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            continue;
        }

        let script = input
            .tap_scripts
            .first_key_value()
            .expect("One script path")
            .1
             .0
            .clone();
        let script_path = ScriptPath::with_defaults(script.as_script());
        let sighash = cache
            .taproot_script_spend_signature_hash(
                index,
                &prevouts,
                script_path.clone(),
                bdk::bitcoin::sighash::TapSighashType::All,
            )
            .unwrap();

        // Sign with the FROST key share
        let message = Message::raw(&sighash[..]);
        let nonce1 = schnorr_fun::musig::NonceKeyPair::random(&mut rand::rngs::OsRng);
        let (index, share) = shares.first_key_value().expect("no shares");
        let nonces = BTreeMap::from_iter([(index.clone(), nonce1.public())]);
        let session = frost.start_sign_session(&xonly_frost_key, nonces, message);
        let sig_share = frost.sign(&xonly_frost_key, &session, index.clone(), share, nonce1);
        let combined_sig =
            frost.combine_signature_shares(&xonly_frost_key, &session, vec![sig_share]);
        info!(?combined_sig, "Combined FROST Signature");
        assert!(frost
            .schnorr
            .verify(&xonly_frost_key.public_key(), message, &combined_sig));

        // Add signature to PSBT
        let sig = Signature::from_slice(&combined_sig.to_bytes()).unwrap();
        input
            .tap_script_sigs
            .insert((xonly_key, script_path.leaf_hash()), sig);
    }
}
