mod test;
use dep::aztec::macros::aztec;

#[aztec]
pub contract EasyPrivateVoting {
    use dep::authwit::entrypoint::{app::AppPayload, fee::FeePayload};
    use dep::aztec::{
        keys::getters::get_public_keys,
        macros::{functions::{initializer, internal, private, public, utility}, storage::storage},
        protocol_types::{
            constants::GENERATOR_INDEX__TX_NULLIFIER, hash::poseidon2_hash_with_separator,
        },
    };
    use dep::aztec::prelude::{AztecAddress, Map, PublicImmutable, PublicMutable};
    use dep::aztec::protocol_types::traits::{Hash, ToField};
    use jwt::JWT;

    global MAX_DATA_LENGTH: u32 = 512;
    global MAX_NONCE_LENGTH: u32 = 32;

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>, // admin can end vote
        tally: Map<Field, PublicMutable<Field, Context>, Context>, // we will store candidate as key and number of votes as value
        vote_ended: PublicMutable<bool, Context>, // vote_ended is boolean
        active_at_block: PublicImmutable<u32, Context>, // when people can start voting
    }

    #[public]
    #[initializer]
    // annotation to mark function as a constructor
    fn constructor(admin: AztecAddress) {
        storage.admin.write(admin);
        storage.vote_ended.write(false);
        storage.active_at_block.initialize(context.block_number() as u32);
    }

    #[private]
    fn entrypoint(
        // Entrypoint parameters
        app_payload: AppPayload,
        fee_payload: FeePayload,
        cancellable: bool,
        // JWT parameters
        data: [u8; MAX_DATA_LENGTH],
        base64_decode_offset: u32,
        pubkey_modulus_limbs: pub [u128; 18],
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
        expected_nonce: pub [u8; MAX_NONCE_LENGTH],
    ) {
        // Safety: count the number of non-zero bytes in the data
        let len = unsafe { data_length(data) };

        let mut vec: BoundedVec<u8, MAX_DATA_LENGTH> = BoundedVec::from_parts(data, len);

        let jwt = JWT::init(
            //data_trimmed,
            vec,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
        );

        jwt.verify();

        // let claim_value: BoundedVec<u8, MAX_DATA_LENGTH> =
        //     BoundedVec::from_array("foobar".as_bytes());

        // jwt.assert_claim_string("data".as_bytes(), claim_value);

        fee_payload.execute_calls(&mut context);
        context.end_setup();
        app_payload.execute_calls(&mut context);
        if cancellable {
            let tx_nullifier =
                poseidon2_hash_with_separator([app_payload.nonce], GENERATOR_INDEX__TX_NULLIFIER);
            context.push_nullifier(tx_nullifier);
        }
    }

    // #[contract_library_method]
    // fn is_valid_impl(_context: &mut PrivateContext, outer_hash: Field) -> bool {
    //     // Load auth witness and format as an u8 array

    //     // Safety: The witness is only used as a "magical value" that makes the signature verification below pass.
    //     // Hence it's safe.
    //     // let witness: [Field; 64] = unsafe { get_auth_witness(outer_hash) };
    //     // let mut signature: [u8; 64] = [0; 64];
    //     // for i in 0..64 {
    //     //     signature[i] = witness[i] as u8;
    //     // }

    //     // // Verify signature using hardcoded public key
    //     // schnorr::verify_signature(public_key, signature, outer_hash.to_be_bytes::<32>())

    //     // TODO: verify the oauth JWT here

    //     true
    // }

    // #[private]
    // fn validate_jwt(
    //     //data: BoundedVec<u8, MAX_DATA_LENGTH>,
    //     data: [u8; MAX_DATA_LENGTH],
    //     //data: [u8; 268],
    //     base64_decode_offset: u32,
    //     pubkey_modulus_limbs: pub [u128; 18],
    //     redc_params_limbs: [u128; 18],
    //     signature_limbs: [u128; 18],
    //     expected_nonce: pub [u8; MAX_NONCE_LENGTH],
    // ) {
    //     // Safety: padded zeroes mess up the jwt logic
    //     let data_trimmed = unsafe { trim_zeros(data) };

    //     let jwt = JWT::init(
    //         data_trimmed,
    //         base64_decode_offset,
    //         pubkey_modulus_limbs,
    //         redc_params_limbs,
    //         signature_limbs,
    //     );

    //     jwt.verify();

    //     let claim_value: BoundedVec<u8, MAX_DATA_LENGTH> =
    //         BoundedVec::from_array("foobar".as_bytes());

    //     jwt.assert_claim_string("data".as_bytes(), claim_value);
    // }

    #[private]
    // annotation to mark function as private and expose private context
    fn cast_vote(candidate: Field) {
        let msg_sender_npk_m_hash = get_public_keys(context.msg_sender()).npk_m.hash();

        let secret = context.request_nsk_app(msg_sender_npk_m_hash); // get secret key of caller of function
        let nullifier = std::hash::pedersen_hash([context.msg_sender().to_field(), secret]); // derive nullifier from sender and secret
        context.push_nullifier(nullifier);
        EasyPrivateVoting::at(context.this_address()).add_to_tally_public(candidate).enqueue(
            &mut context,
        );
    }

    #[public]
    #[internal]
    fn add_to_tally_public(candidate: Field) {
        assert(storage.vote_ended.read() == false, "Vote has ended"); // assert that vote has not ended
        let new_tally = storage.tally.at(candidate).read() + 1;
        storage.tally.at(candidate).write(new_tally);
    }

    #[public]
    fn end_vote() {
        assert(storage.admin.read().eq(context.msg_sender()), "Only admin can end votes"); // assert that caller is admin
        storage.vote_ended.write(true);
    }
    #[utility]
    unconstrained fn get_vote(candidate: Field) -> Field {
        storage.tally.at(candidate).read()
    }

    #[utility]
    unconstrained fn data_length(input: [u8; MAX_DATA_LENGTH]) -> u32 {
        let mut length: u32 = 0;
        for i in 0..MAX_DATA_LENGTH {
            if input[i] == 0 {
                length = i;
                break;
            }
        }

        if length == 0 {
            MAX_DATA_LENGTH
        } else {
            length
        }
    }
}
