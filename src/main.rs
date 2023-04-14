use curv::{BigInt, elliptic::curves::{Point, Secp256k1}};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

// Server structure definition, holding party1's (P1) key shares and related data
pub struct Server {
    ec_key_pair_party1: party_one::EcKeyPair,                   // P1's EC key pair
    keypair: party_one::PaillierKeyPair,                        // P1's Paillier key pair
    // Signature
    eph_ec_key_pair_party1: Option<party_one::EphEcKeyPair>,    // P1's ephemeral EC key pair
    party1_private: Option<party_one::Party1Private>            // P1's private key
}

// Structure holding server's signing data required by the client (P2)
pub struct ServerSigningData {
    paillier_key_pair_ek: paillier::EncryptionKey,              // P1's Paillier encryption key
    paillier_key_pair_encrypted_share: BigInt,                  // Encrypted share of P1's Paillier private key
    eph_party_one_first_message: party_one::EphKeyGenFirstMsg,  // P1's ephemeral key pair generation first message
}

impl Server {

    // Initialize the server (P1) with key generation
    pub fn new () -> Self { 

        // P1's EC key pair generation
        let (_, _comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();  

        // P1's Paillier key pair generation
        let keypair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1); 

        Self {
            ec_key_pair_party1,
            keypair,
            eph_ec_key_pair_party1: None,
            party1_private: None
        }
    }

    // Compute the shared public key
    pub fn get_party_one_pubkey(&self, ec_key_pair_party2_public_share: &Point<Secp256k1>) -> Point<Secp256k1> {
        let party1_private = self.party1_private.as_ref().expect("Server's party1_private not available");

        party_one::compute_pubkey(&party1_private, &ec_key_pair_party2_public_share)
    }

    // P1 generates ephemeral key pair and shares public key with P2 (start signing process)
    pub fn start_signing(&mut self) -> ServerSigningData {
        // creating the ephemeral private shares (k1):
        let (eph_party_one_first_message, eph_ec_key_pair_party1) =
            party_one::EphKeyGenFirstMsg::create(); // P1's ephemeral key pair generation

        self.eph_ec_key_pair_party1 = Some(eph_ec_key_pair_party1);

        let party1_private = party_one::Party1Private::set_private_key(&self.ec_key_pair_party1, &self.keypair);  // Set P1's private key
        self.party1_private = Some(party1_private);

        // Return P1's Paillier public key, encrypted share and ephemeral public key
        ServerSigningData {
            paillier_key_pair_ek: self.keypair.ek.clone(),
            paillier_key_pair_encrypted_share: self.keypair.encrypted_share.clone(),
            eph_party_one_first_message
        }
    }

    // P1 finishes the signing process and computes the signature
    pub fn finish_signing(&self, client_partial_sig: &ClientPartialSig) -> party_one::BlindedSignature {

        let party1_private = self.party1_private.as_ref().expect("Server's party1_private not available");
        let eph_ec_key_pair_party1 = self.eph_ec_key_pair_party1.as_ref().expect("Server's eph_ec_key_pair_party1 not available");

        let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &client_partial_sig.eph_party_two_first_message,
                &client_partial_sig.eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof"); // Verify the second message of P2's ephemeral key pair generation


        let signature = party_one::Signature::compute_blinded(
            party1_private,
            &client_partial_sig.partial_sig.c3,
            eph_ec_key_pair_party1,
        ); // Compute the signature

        signature
    }

    pub fn verify_signature(&self, signature: &party_one::Signature, party_two_private_share_gen_public_share: &Point<Secp256k1>, message: &BigInt) {
        let party1_private = self.party1_private.as_ref().expect("Server's party1_private not available");

        let pubkey =
            party_one::compute_pubkey(party1_private, party_two_private_share_gen_public_share);
        party_one::verify(signature, &pubkey, message).expect("Invalid signature")
    }
}

// Client structure definition, holding party2's (P2) key shares and related data
pub struct Client {
    party_two_private_share_gen: party_two::KeyGenFirstMsg,     // P2's private share key generation first message
    ec_key_pair_party2: party_two::EcKeyPair                    // P2's EC key pair
}

// Structure holding P2's partially signed data
pub struct ClientPartialSig {
    eph_party_two_first_message: party_two::EphKeyGenFirstMsg,      // P2's ephemeral key pair generation first message
    eph_party_two_second_message: party_two::EphKeyGenSecondMsg,    // P2's ephemeral key pair generation second message
    partial_sig: party_two::PartialBlindedSig                       // P2's partially signed data
    
}

impl Client {

    pub fn new () -> Self {

        let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create(); // P2's private share key generation

        Self {
            party_two_private_share_gen,
            ec_key_pair_party2
        }
    }

    // Get P2's public share key
    pub fn get_party_two_private_share_gen_public_share(&self) -> Point<Secp256k1> {
        self.party_two_private_share_gen.public_share.clone()
    }

    // Get P2's EC key pair public share key
    pub fn get_ec_key_pair_party2_public_share(&self) -> Point<Secp256k1> {
        self.ec_key_pair_party2.public_share.clone()
    }

    // P2 partially signs the message
    pub fn partially_sign(&self, server_signing_data: &ServerSigningData, message: &BigInt ) -> ClientPartialSig {

        // creating the ephemeral private shares (k2):
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            party_two::EphKeyGenFirstMsg::create_commitments(); // P2's ephemeral key pair generation
        
        let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            &server_signing_data.eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");  // Verify the second message of P1's ephemeral key pair generation

        let party2_private = party_two::Party2Private::set_private_key(&self.ec_key_pair_party2);

        let partial_sig = party_two::PartialSig::compute_blinded(
            &server_signing_data.paillier_key_pair_ek,
            &server_signing_data.paillier_key_pair_encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &server_signing_data.eph_party_one_first_message.public_share,
            &message,
        ); // Compute P2's partially signed data

        ClientPartialSig {
            eph_party_two_first_message,
            eph_party_two_second_message,
            partial_sig
        }  
    }

    pub fn verify_signature(&self, signature: &party_one::Signature, party_one_pubkey: &Point<Secp256k1>, message: &BigInt) {

        party_one:: verify(
            signature,
            &party_one_pubkey,
            &message,
        ).expect("Invalid signature")
    }
    
}

fn main() {
    let message = BigInt::from(1234);  // Known message

    let mut server = Server::new(); // Initialize the server (P1) with key generation
    let server_signing_data = server.start_signing(); // P1 generates ephemeral key pair and shares public key with P2 (start signing process)

    let client = Client::new(); // Initialize the client (P2) with private share key generation
    let client_partial_sig = client.partially_sign(&server_signing_data, &message); // P2 partially signs the message

    let blinded_signature = server.finish_signing(&client_partial_sig); // P1 finishes signing the message with P2's partially signed data

    let signature = party_one::Signature {
        r: client_partial_sig.partial_sig.r,
        s: blinded_signature.s,
    };

    let party_two_private_share_gen_public_share = client.get_party_two_private_share_gen_public_share(); // Get P2's public share key
    server.verify_signature(&signature, &party_two_private_share_gen_public_share, &message); // Verify the signature

    let ec_key_pair_party2_public_share = &client.get_ec_key_pair_party2_public_share(); // Get P2's EC key pair public share key
    let party_one_pubkey = server.get_party_one_pubkey(ec_key_pair_party2_public_share); // Compute the shared public key
    client.verify_signature(&signature, &party_one_pubkey, &message); // Verify the signature
}
