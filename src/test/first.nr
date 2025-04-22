use crate::test::utils;
use dep::aztec::oracle::{execution::get_block_number, storage::storage_read};
use dep::aztec::protocol_types::storage::map::derive_storage_slot_in_map;

use crate::EasyPrivateVoting;

#[test]
unconstrained fn validate_jwt_token() {
    let (env, voting_contract_address, _) = utils::setup();
    let alice = env.create_account(2);

    let data = [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let offset = 37;

    let pubkey_modulus_limbs: [u128; 18] = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];

    let redc_params_limbs: [u128; 18] = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];

    let signature_limbs: [u128; 18] = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];

    env.impersonate(alice);

    EasyPrivateVoting::at(voting_contract_address)
        .validate_jwt(
            data,
            offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            [0; 32],
        )
        .call(&mut env.private());
}

#[test]
unconstrained fn test_initializer() {
    let (_, voting_contract_address, admin) = utils::setup();

    let block_number = get_block_number();
    let admin_slot = EasyPrivateVoting::storage_layout().admin.slot;
    let admin_storage_value = storage_read(voting_contract_address, admin_slot, block_number);
    assert(admin_storage_value == admin, "Vote ended should be false");
}

#[test]
unconstrained fn test_check_vote_status() {
    let (_, voting_contract_address, _) = utils::setup();

    let vote_ended_expected: bool = false;

    let block_number = get_block_number();
    let status_slot = EasyPrivateVoting::storage_layout().vote_ended.slot;
    let vote_ended_read: bool = storage_read(voting_contract_address, status_slot, block_number);
    assert(vote_ended_expected == vote_ended_read, "Vote ended should be false");
}

#[test]
unconstrained fn test_end_vote() {
    let (env, voting_contract_address, admin) = utils::setup();

    env.impersonate(admin);
    EasyPrivateVoting::at(voting_contract_address).end_vote().call(&mut env.public());

    let vote_ended_expected = true;

    let block_number = get_block_number();
    let status_slot = EasyPrivateVoting::storage_layout().vote_ended.slot;
    let vote_ended_read: bool = storage_read(voting_contract_address, status_slot, block_number);
    assert(vote_ended_expected == vote_ended_read, "Vote ended should be true");
}

#[test(should_fail)]
unconstrained fn test_fail_end_vote_by_non_admin() {
    let (env, voting_contract_address, _) = utils::setup();
    let alice = env.create_account(2);

    env.impersonate(alice);
    EasyPrivateVoting::at(voting_contract_address).end_vote().call(&mut env.public());
}

#[test]
unconstrained fn test_cast_vote() {
    let (env, voting_contract_address, _) = utils::setup();
    let alice = env.create_account(2);
    env.impersonate(alice);

    let candidate = 1;
    env.advance_block_by(6);
    EasyPrivateVoting::at(voting_contract_address).cast_vote(candidate).call(&mut env.private());

    // Read vote count from storage
    let block_number = get_block_number();
    let tally_slot = EasyPrivateVoting::storage_layout().tally.slot;
    let candidate_tally_slot = derive_storage_slot_in_map(tally_slot, candidate);
    let vote_count: u32 = storage_read(voting_contract_address, candidate_tally_slot, block_number);

    assert(vote_count == 1, "vote tally should be incremented");
}

#[test]
unconstrained fn test_cast_vote_with_separate_accounts() {
    let (env, voting_contract_address, _) = utils::setup();
    let alice = env.create_account(2);
    let bob = env.create_account(3);

    let candidate = 101;

    env.impersonate(alice);
    env.advance_block_by(1);
    EasyPrivateVoting::at(voting_contract_address).cast_vote(candidate).call(&mut env.private());

    env.impersonate(bob);
    env.advance_block_by(1);
    EasyPrivateVoting::at(voting_contract_address).cast_vote(candidate).call(&mut env.private());

    // Read vote count from storage
    let block_number = get_block_number();
    let tally_slot = EasyPrivateVoting::storage_layout().tally.slot;
    let candidate_tally_slot = derive_storage_slot_in_map(tally_slot, candidate);
    let vote_count: u32 = storage_read(voting_contract_address, candidate_tally_slot, block_number);

    assert(vote_count == 2, "vote tally should be 2");
}

#[test(should_fail)]
unconstrained fn test_fail_vote_twice() {
    let (env, voting_contract_address, _) = utils::setup();
    let alice = env.create_account(2);

    let candidate = 101;

    env.impersonate(alice);
    env.advance_block_by(1);
    EasyPrivateVoting::at(voting_contract_address).cast_vote(candidate).call(&mut env.private());

    // Vote again as alice
    env.advance_block_by(1);
    EasyPrivateVoting::at(voting_contract_address).cast_vote(candidate).call(&mut env.private());
}
