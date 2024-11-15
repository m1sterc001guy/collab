use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Network, PrivateKey, PublicKey};
use bdk::blockchain::EsploraBlockchain;
use bdk::database::MemoryDatabase;
use bdk::keys::{GeneratableDefaultOptions, GeneratedKey};
use bdk::miniscript::descriptor::TapTree;
use bdk::miniscript::policy::Concrete;
use bdk::miniscript::{miniscript, Descriptor};
use bdk::signer::{SignerContext, SignerOrdering, SignerWrapper};
use bdk::wallet::AddressIndex;
use bdk::{FeeRate, KeychainKind, SignOptions, SyncOptions, Wallet};
use fedimint_testing::envs::FM_PORT_ESPLORA_ENV;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        //let gw_lnd = dev_fed.gw_lnd().await?;
        //let info = gw_lnd.get_info().await?;
        //info!(?info, "GW LND Info");

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

        let private_key3: GeneratedKey<_, miniscript::Tap> = PrivateKey::generate_default()?;
        let private_key3 = private_key3.into_key();
        let public_key3 = PublicKey::from_private_key(&secp, &private_key3);

        let keys = [public_key1, public_key2, public_key3];

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
            .generate_to_address(200, &address.address)
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

        //info!(?psbt, "PSBT");
        info!(?details, "TransactionDetails");

        sign_psbt(&mut wallet, private_key2, &mut psbt);
        sign_psbt(&mut wallet, private_key3, &mut psbt);

        let tx = psbt.extract_tx();
        //info!(?tx, "Transaction");
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
