mod test;
use dep::aztec::macros::aztec;
//use jwt::JWT;

#[aztec]
pub contract EasyPrivateVoting {
    use dep::aztec::{
        keys::getters::get_public_keys,
        macros::{functions::{initializer, internal, private, public, utility}, storage::storage},
    };
    use dep::aztec::prelude::{AztecAddress, Map, PublicImmutable, PublicMutable};
    use dep::aztec::protocol_types::traits::{Hash, ToField};
    //use easy_private_state::EasyPrivateUint;
    use jwt::JWT;

    global MAX_DATA_LENGTH: u32 = 900;
    //global MAX_CLAIM_LENGTH: u32 = 64;
    global MAX_NONCE_LENGTH: u32 = 32; // we are verifying `nonce` claim

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>, // admin can end vote
        tally: Map<Field, PublicMutable<Field, Context>, Context>, // we will store candidate as key and number of votes as value
        vote_ended: PublicMutable<bool, Context>, // vote_ended is boolean
        active_at_block: PublicImmutable<u32, Context>, // when people can start voting
        //used_nonces: [Field; 1000000], // array of used nonces
        //nonces: Map<AztecAddress, EasyPrivateUint<Context>, Context>,
    }

    #[public]
    #[initializer]
    // annotation to mark function as a constructor
    fn constructor(admin: AztecAddress) {
        storage.admin.write(admin);
        storage.vote_ended.write(false);
        storage.active_at_block.initialize(context.block_number() as u32);
        //storage.used_nonces.initialize([0; 1000000]);
    }

    #[private]
    fn validate_jwt(
        data: [u8; MAX_DATA_LENGTH],
        base64_decode_offset: u32,
        pubkey_modulus_limbs: pub [u128; 18],
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
        expected_nonce: pub [u8; MAX_NONCE_LENGTH],
    ) {
        let data_vec: BoundedVec<u8, MAX_DATA_LENGTH> = BoundedVec::from_array(data);
        let expected_nonce_vec: BoundedVec<u8, MAX_NONCE_LENGTH> =
            BoundedVec::from_array(expected_nonce);

        let jwt = JWT::init(
            data_vec,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
        );

        jwt.verify();

        //let test_sub: BoundedVec<u8, 3> = BoundedVec::from_array([49, 50, 52]);
        //jwt.assert_claim_string("sub".as_bytes(), test_sub);
        //jwt.assert_claim_string("sub".as_bytes(), expected_sub);
        //private_call.transfer(to, amount);
    }

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
}
