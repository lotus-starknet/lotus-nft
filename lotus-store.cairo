%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.starknet.common.syscalls import (
    get_caller_address,
    get_contract_address,
    get_block_timestamp,
)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import (
    assert_not_zero,
    split_felt,
    assert_lt_felt,
    unsigned_div_rem,
)
from starkware.cairo.common.uint256 import Uint256, uint256_le, assert_uint256_le, uint256_add
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from openzeppelin.token.erc20.IERC20 import IERC20
from lotusRaffle.randomGenerator import next
from openzeppelin.access.ownable.library import Ownable
from openzeppelin.security.pausable.library import Pausable
from openzeppelin.security.reentrancyguard.library import ReentrancyGuard
from openzeppelin.upgrades.library import Proxy
from openzeppelin.token.erc721.IERC721 import IERC721
from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.utils.constants.library import (
    IERC721_RECEIVER_ID,
)

const RAFFLE_ONGOING = 1;
const RAFFLE_DRAW_PENDING = 2;
const RAFFLE_FINISHED = 3;
const RAFFLE_CANCELLED = 4;

struct Raffle{
    creator : felt,
    nftContractAddress : felt,
    nftTokenId : Uint256,
    endDate : felt,
    ticketPrice : felt,
    totalTicketSupply : felt,
    totalSoldTicket : felt,
    status : felt, // ONGOING - FINISHED
    totalParticipants : felt,
}

struct Participant {
    boughtTicket : felt,
    participantAddress : felt,
}

@storage_var
func random_state() -> (seed: felt) {
}

@storage_var
func isNftRefunded(raffle_id : felt) -> (res: felt) {
}

@storage_var
func verifiedCollection(collection_address : felt) -> (res: felt) {
}

@storage_var
func fee_address() -> (res: felt) {
}

@storage_var
func fee_rate() -> (res: felt) {
}

@storage_var
func raffle_info(raffle_id : felt) -> (res: Raffle) {
}

@storage_var
func raffle_ids(counter : felt) -> (raffle_id: felt) {
}

@storage_var
func raffles_count() -> (counter: felt) {
}

@storage_var
func minTicketSupply() -> (res: felt) {
}

@storage_var
func raffle_participants(raffle_id : felt, id : felt) -> (participant: felt) {
}

@storage_var
func creator_raffle_count(user_address : felt) -> (count : felt) {
}

@storage_var
func creator_raffle(user_address : felt, id : felt) -> (raffle_id : felt) {
}

@storage_var
func user_raffle_info(user_address : felt, raffle_id : felt) -> (participant: Participant) {
}

@storage_var
func raffle_winner(raffle_id : felt) -> (winner : felt) {
}

@storage_var
func payment_token() -> (token : felt) {
}

@storage_var
func sgn_contract() -> (addr : felt) {
}

@storage_var
func lotus_contract() -> (addr : felt) {
}




@event
func new_raffle_created(raffle_id : felt, nft_contract_address : felt, creator : felt, token_id : Uint256, endTime : felt, ticketPrice : felt, totalTicketSupply : felt, time : felt) {
}

@event
func draw_completed(raffle_id : felt, raffle_status : felt, winner : felt) {
}

@event
func ticket_purchased(raffle_id : felt, purchased_by : felt, amount : felt, total_sold_ticket : felt, total_participants : felt, user_total_ticket : felt) {
}

@event
func refund_taken(raffle_id : felt, taken_by : felt, ticket_amount : felt, total_sold_ticket : felt, total_participants : felt) {
}



@external
func initializer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    manager : felt, ether : felt, _fee_rate : felt, fee_addr : felt, seed : felt, _lotus_contract: felt, _sgn_contract : felt
) {
    let (_manager) = Ownable.owner();
    with_attr error_message("raffleStore:: woot! already initilaized"){
        assert _manager = 0;
    }
    payment_token.write(ether);
    random_state.write(seed);
    lotus_contract.write(_lotus_contract);
    sgn_contract.write(_sgn_contract);
    fee_address.write(fee_addr);
    fee_rate.write(_fee_rate);
    ERC165.register_interface(IERC721_RECEIVER_ID);
    Ownable.initializer(manager);
    verifiedCollection.write(0x03090623ea32d932ca1236595076b00702e7d860696faf300ca9eb13bfe0a78c, TRUE);
    verifiedCollection.write(0x07b6d00f28db723199bb54ca74a879a5102c44141f0e93674b2cb25f8f253c62, TRUE);
    verifiedCollection.write(0x0564742bd75538e017a0ba7f23c9b6746d956458ce76e9d00e9182ba0b934acd, TRUE);
    verifiedCollection.write(0x07ffe4bd0b457e10674a2842164b91fea646ed4027d3b606a0fcbf056a4c8827, TRUE);
    
    return();
}

@view
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    interfaceId: felt
) -> (success: felt) {
    let (success) = ERC165.supports_interface(interfaceId);
    return (success,);
}


@view
func owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (owner: felt) {
    let (owner: felt) = Ownable.owner();
    return (owner,);
}

@view
func getFeeDetails{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (fee_addr: felt, fee_rate : felt) {
    let addr : felt = fee_address.read();
    let rate : felt = fee_rate.read();
    return (addr,rate,);
}

//getUsersRaffles

@view
func getRaffleInfo{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
     raffleId : felt
) -> (raffle_data : Raffle) { 
    let raffle_data : Raffle = raffle_info.read(raffleId);
    return (raffle_data,);
}

@view
func getWinner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
     raffleId : felt
) -> (winner : felt) { 
    let _winner : felt = raffle_winner.read(raffleId);
    return (_winner,);
}

@view
func getUserRaffleInfo{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
     raffleId : felt, user_address : felt
) -> (participant_ : Participant) { 
    let participant_data : Participant = user_raffle_info.read(user_address, raffleId);
    return (participant_data,);
}


@view
func getParticipantsOfRaffle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    start: felt, end: felt, raffleId : felt
) -> (participants_len: felt, participants : Participant*) { 
    alloc_locals;
    let (participants_len, participants) = getRecursivelyParticipantsOfRaffle(raffleId, start, end);
    return (participants_len, participants - participants_len * Participant.SIZE);
}


@view
func getRaffles{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    start: felt, end: felt, forUser : felt, user_address : felt
) -> (raffles_len: felt, raffles : Raffle*) { 
    alloc_locals;
    if(forUser == TRUE){
        let (ids_len : felt, ids : felt*) = getRaffleIdsForUser(start, end, user_address);
        let (raffles_len, raffles) = getRecursivelyRaffle(ids_len, ids - ids_len, 0);
        return (raffles_len, raffles - raffles_len * Raffle.SIZE);
    }else{
        let (ids_len : felt, ids : felt*) = getRaffleIds(start, end);
        let (raffles_len, raffles) = getRecursivelyRaffle(ids_len, ids - ids_len, 0);
        return (raffles_len, raffles - raffles_len * Raffle.SIZE);
    }
}

@view
func getRaffleStatus{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
     raffleId : felt
) -> (res : felt) { 
    let raffle_data : Raffle = raffle_info.read(raffleId);
    let (now) = get_block_timestamp();
    let is_ended : felt = is_le(raffle_data.endDate, now);
    if(raffle_data.totalTicketSupply == 0){
        return (0,);
    }
    if(raffle_data.totalSoldTicket == raffle_data.totalTicketSupply){
        if(raffle_data.status == RAFFLE_ONGOING){
            return (RAFFLE_DRAW_PENDING,);
        }
        return (RAFFLE_FINISHED,);
    }
    if(is_ended == TRUE){
        let is_sold_ticket_above_limit : felt = is_le(raffle_data.totalTicketSupply / 2, raffle_data.totalSoldTicket);
        
        if(is_sold_ticket_above_limit == FALSE){
            return (RAFFLE_CANCELLED,);
        }

        if(raffle_data.status == RAFFLE_ONGOING){
            return (RAFFLE_DRAW_PENDING,);
        }

        return (RAFFLE_FINISHED,);
    }

    return (RAFFLE_ONGOING,);
}

//externals

@external
func drawWinner{pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, syscall_ptr: felt*, range_check_ptr}(raffle_id : felt){
    alloc_locals;
    ReentrancyGuard.start();
    let (current_raffle_status) = getRaffleStatus(raffle_id);  
    let raffle_data : Raffle = raffle_info.read(raffle_id);
    with_attr error_message("lotusRaffle::drawWinner woot! raffle is not available for draw"){
        assert current_raffle_status = RAFFLE_DRAW_PENDING; 
    }
    let (winner_address) = findWinner(raffle_id, raffle_data.totalSoldTicket);
    let (fee_deducted_raised) = deductFee(raffle_data.ticketPrice, raffle_data.totalSoldTicket, raffle_data.creator);
    let (this) = get_contract_address();
    transferNft(raffle_data.nftContractAddress, raffle_data.nftTokenId, this, winner_address);
    transferFund(fee_deducted_raised, raffle_data.creator);
    let updated_raffle : Raffle = Raffle(raffle_data.creator, raffle_data.nftContractAddress, raffle_data.nftTokenId, raffle_data.endDate, raffle_data.ticketPrice, raffle_data.totalTicketSupply, raffle_data.totalSoldTicket, RAFFLE_FINISHED, raffle_data.totalParticipants);
    raffle_info.write(raffle_id, updated_raffle);
    raffle_winner.write(raffle_id, winner_address);
    draw_completed.emit(raffle_id, RAFFLE_FINISHED, winner_address);
    ReentrancyGuard.end();
    return ();
}

@external
func refundTicketFee{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(raffle_id : felt){
    alloc_locals;
    ReentrancyGuard.start();
    let (current_raffle_status) = getRaffleStatus(raffle_id);  
    with_attr error_message("lotusRaffle::refundTicketFee woot! raffle is not available for refund"){
        assert current_raffle_status = RAFFLE_CANCELLED; 
    }
    let raffle_data : Raffle = raffle_info.read(raffle_id);
    let (msg_sender) = get_caller_address();
    let (this) = get_contract_address();
    let (user_info) = user_raffle_info.read(msg_sender, raffle_id);
    checkIsRefundAvailable(raffle_data.creator, msg_sender, user_info.boughtTicket);
    transferFund(user_info.boughtTicket * raffle_data.ticketPrice, msg_sender);
    let _isNftRefunded : felt = isNftRefunded.read(raffle_id);
    refundNftIfAvailable(_isNftRefunded, this, raffle_data, raffle_id);
    let updated_raffle : Raffle = Raffle(raffle_data.creator, raffle_data.nftContractAddress, raffle_data.nftTokenId, raffle_data.endDate, raffle_data.ticketPrice, raffle_data.totalTicketSupply, raffle_data.totalSoldTicket - user_info.boughtTicket, raffle_data.status, raffle_data.totalParticipants - 1);
    let updated_user : Participant = Participant(0, msg_sender);
    raffle_info.write(raffle_id, updated_raffle);
    user_raffle_info.write(msg_sender, raffle_id, updated_user);
    refund_taken.emit(raffle_id, msg_sender, user_info.boughtTicket, raffle_data.totalSoldTicket - user_info.boughtTicket, raffle_data.totalParticipants - 1);
    ReentrancyGuard.end();
    return ();
}

@external
func createRaffle{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(random_raffle_id : felt, _nft_contract_address : felt, _token_id : Uint256, endTime : felt, totalTicketSupply : felt, ticketPrice : felt) {
    alloc_locals;
    ReentrancyGuard.start();
    let (msg_sender) = get_caller_address();
    let (this) = get_contract_address();

    let (l_address) = lotus_contract.read();
    let (sgn_address) = sgn_contract.read();
    
    //TODO ENABLE - CHECKNFTBALANCE CHECKING ON MAINNET
    //checkNftBalance(msg_sender, l_address, sgn_address);

    let (raffle_data) = alloc();
    assert raffle_data[0] = _nft_contract_address;
    assert raffle_data[1] = endTime;
    assert raffle_data[2] = ticketPrice;
    assert raffle_data[3] = totalTicketSupply;
    assert raffle_data[4] = random_raffle_id;
    
    IERC721.safeTransferFrom(_nft_contract_address, msg_sender, this, _token_id, 5, raffle_data);
    ReentrancyGuard.end();
    return ();
}

@external
func buyTicket{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(raffle_id : felt, ticket_count : felt) {
    alloc_locals;
    ReentrancyGuard.start();
    let (msg_sender) = get_caller_address();
    let (this) = get_contract_address();
    let (now) = get_block_timestamp();
    let (current_raffle_status) = getRaffleStatus(raffle_id);  
   
    with_attr error_message("lotusRaffleCreator::buyTicket woot! raffle is not available"){
        assert current_raffle_status = RAFFLE_ONGOING;
    }

    let raffle_data : Raffle = raffle_info.read(raffle_id);
    
    let is_sold_amount_less_than_limit : felt = is_le(raffle_data.totalSoldTicket + ticket_count, raffle_data.totalTicketSupply);
    with_attr error_message("lotusRaffleCreator::buyTicket woot! supply limit exceed"){
        assert is_sold_amount_less_than_limit = TRUE;
    }

    let ticket_cost : felt = ticket_count * raffle_data.ticketPrice;
    let _payment_token : felt = payment_token.read();
    let cost_as_uint : Uint256 = felt_to_uint256(ticket_cost);
    let (success) = IERC20.transferFrom(_payment_token, msg_sender, this, cost_as_uint);
    with_attr error_message("lotusRaffleCreator::buyTicket woot! not enough balance for ticket cost"){
        assert success = TRUE;
    }
    let (user_info) = user_raffle_info.read(msg_sender, raffle_id);
    let updated_participant_count : felt = returnUpdatedParticipantCount(user_info.boughtTicket, raffle_data.totalParticipants);

    let user_updated_ticket_count : felt = user_info.boughtTicket + ticket_count; 
    maxTicketPurchaseCheck(raffle_data.totalTicketSupply, user_updated_ticket_count);
    let updated_raffle : Raffle = Raffle(raffle_data.creator, raffle_data.nftContractAddress, raffle_data.nftTokenId, raffle_data.endDate, raffle_data.ticketPrice, raffle_data.totalTicketSupply, raffle_data.totalSoldTicket + ticket_count, raffle_data.status, updated_participant_count);
    let updated_user : Participant = Participant(user_updated_ticket_count, msg_sender);
    
    recursivelyAddtoList(raffle_id, msg_sender, raffle_data.totalSoldTicket, ticket_count, 0);
    raffle_info.write(raffle_id, updated_raffle);
    user_raffle_info.write(msg_sender, raffle_id, updated_user);
    ticket_purchased.emit(raffle_id, msg_sender, ticket_count, raffle_data.totalSoldTicket + ticket_count, updated_participant_count, user_updated_ticket_count);
    ReentrancyGuard.end();
    return ();
}


@external
func onERC721Received{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(_from : felt, _to : felt, token_id : Uint256, data_len : felt, data : felt*) -> (res : felt) {
    alloc_locals;
    let (now) = get_block_timestamp();
    let raffle_data : Raffle = raffle_info.read(data[4]);
    with_attr error_message("lotus_raffle:raffle already inited"){
        assert raffle_data.nftContractAddress = 0;
    }
    //TODO ONLY MAINNET
    //onlyWhitelistedCollections(data[0]);
    with_attr error_message("createRaffle::onERC721Recived must end in 10 days"){
        assert_lt_felt(data[1], now + 864000);
    }

    let min_tick_limit : felt = minTicketSupply.read();
    let is_supply_above_min : felt = is_le(min_tick_limit, data[3]);

    with_attr error_message("createRaffle::onERC721Recived less than min limit"){
        assert is_supply_above_min = TRUE;
    }

    let new_raffle : Raffle = Raffle(_to, data[0], token_id, data[1], data[2], data[3], 0, RAFFLE_ONGOING, 0);
    raffle_info.write(data[4], new_raffle);
    
    let old_raffle_count : felt = raffles_count.read();
    raffle_ids.write(old_raffle_count, data[4]);
    raffles_count.write(old_raffle_count + 1);
    
    let user_created_raffle_count : felt = creator_raffle_count.read(_to);
    creator_raffle.write(_to, user_created_raffle_count, data[4]);
    creator_raffle_count.write(_to, user_created_raffle_count + 1);

    let (now) = get_block_timestamp();
    
    new_raffle_created.emit(data[4], data[0], _to, token_id, data[1], data[2], data[3], now);
    return (IERC721_RECEIVER_ID,);
}


@external
func changeMinLimitForTicketSupply{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(min : felt) {
    Ownable.assert_only_owner();
    minTicketSupply.write(min);
    return ();
}

@external
func setVerifiedCollection{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(collectionAddress : felt, bool : felt) {
    Ownable.assert_only_owner();
    verifiedCollection.write(collectionAddress, bool);
    return ();
}

@external
func setFeeSettings{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(_fee_address : felt, _fee_rate : felt) {
    Ownable.assert_only_owner();
    fee_address.write(_fee_address);
    fee_rate.write(_fee_rate);
    return ();
}


@external
func setRandomState{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(r : felt) {
    Ownable.assert_only_owner();
    random_state.write(r);
    return ();
}

@external
func transferOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    newOwner: felt
) {
    Ownable.transfer_ownership(newOwner);
    return ();
}

@external
func renounceOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.renounce_ownership();
    return ();
}

@external
func upgrade{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_implementation: felt
) {
    // Verify that caller is admin
    Ownable.assert_only_owner();
    Proxy._set_implementation_hash(new_implementation);
    return ();
}


// Internals
func getRecursivelyParticipantsOfRaffle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
     raffleId : felt, start : felt, end : felt
) -> (participant_len : felt, participants : Participant*) { 
    alloc_locals;
   
    if (start == end) {
        let (found_participants: Participant*) = alloc();
        return (0, found_participants);
    }
    let _participant_address: felt = raffle_participants.read(raffleId, start);
    let _participant : Participant = user_raffle_info.read(_participant_address, raffleId);

    let (participant_memory_location_len, participant_memory_location: Participant*) = getRecursivelyParticipantsOfRaffle(raffleId, start + 1, end);
    assert [participant_memory_location] = _participant;
    return (participant_memory_location_len + 1, participant_memory_location + Participant.SIZE);
}


func getRecursivelyRaffle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    ids_len: felt, ids: felt*, index : felt 
) -> (raffles_len: felt, raffles : Raffle*) { 
    alloc_locals;
   
    if (ids_len == index) {
        let (found_raffles: Raffle*) = alloc();
        return (0, found_raffles);
    }
    let raffle_details: Raffle = raffle_info.read([ids]);

    let (raffle_memory_location_len, raffle_memory_location: Raffle*) = getRecursivelyRaffle(
        ids_len, ids + 1, index + 1
    );
    assert [raffle_memory_location] = raffle_details;
    return (raffle_memory_location_len + 1, raffle_memory_location + Raffle.SIZE);
}

func getRaffleIds{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    start: felt, end: felt
) -> (raffles_len: felt, raffles : felt*) { 
    alloc_locals;
   
    if (start == end) {
        let (found_ids: felt*) = alloc();
        return (0, found_ids,);
    }
    let raffle_id: felt = raffle_ids.read(start);

    let (ids_memory_location_len, ids_memory_location: felt*) = getRaffleIds(
        start + 1, end
    );
    assert [ids_memory_location] = raffle_id;
    return (ids_memory_location_len + 1, ids_memory_location + 1);
}

func getRaffleIdsForUser{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (
    start: felt, end: felt, user_address : felt
) -> (raffles_len: felt, raffles : felt*) { 
    alloc_locals;
   
    if (start == end) {
        let (found_ids: felt*) = alloc();
        return (0, found_ids,);
    }
     
    let raffle_id: felt = creator_raffle.read(user_address, start);

    let (ids_memory_location_len, ids_memory_location: felt*) = getRaffleIdsForUser(
        start + 1, end, user_address
    );
    assert [ids_memory_location] = raffle_id;
    return (ids_memory_location_len + 1, ids_memory_location + 1);
}

func returnUpdatedParticipantCount{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(user_bought_ticket : felt, current_participant_count : felt) -> (res : felt) {
    if(user_bought_ticket == 0){
        return (current_participant_count + 1,);
    }
    return (current_participant_count,);
}



func getNftBalance{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(user_address : felt, collection_address : felt) -> (res : felt) {
    alloc_locals;
    let (userbalance) = IERC721.balanceOf(collection_address, user_address);
    let balance_as_felt : felt = uint256_to_felt(userbalance);
    return (balance_as_felt,);
}

func checkNftBalance{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(user_address : felt, collection_address : felt, sgn_address : felt) {
    let (balance_as_felt) = getNftBalance(user_address, collection_address);
    let is_less_than_zero = is_le(balance_as_felt, 0);
    if(is_less_than_zero == FALSE){
        return();
    }
    let (balance_as_felt_sgn) = getNftBalance(user_address, sgn_address);
    let is_less_than_zero_sgn = is_le(balance_as_felt_sgn, 0);
    if(is_less_than_zero_sgn == FALSE){
        return();
    }
    with_attr error_message("checkNftBalance::balance is less than zero"){
        assert 1 = 0;
    }
    return ();
}

func get_next_rnd{syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (rnd : felt){
    let (last_random_number) = random_state.read();
    let (rnd) = next(last_random_number);
    random_state.write(rnd);
    return (rnd,);
}

//internal mutations

func recursivelyAddtoList{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(raffle_id : felt, user_address : felt, init_number : felt, loop_size : felt, index : felt){
    alloc_locals;
   
    if (loop_size == index) {
        return ();
    }
    raffle_participants.write(raffle_id, index + init_number, user_address);
    recursivelyAddtoList(raffle_id, user_address, init_number, loop_size, index + 1);
    return ();

}

func findWinner{syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, pedersen_ptr: HashBuiltin*, range_check_ptr}(raffle_id : felt, list_length : felt) -> (winner : felt){
    let (random) = get_next_rnd();
    let (q, rem) = unsigned_div_rem(random, list_length);
    let winner : felt = raffle_participants.read(raffle_id, rem);
    return (winner,);
}


func maxTicketPurchaseCheck{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(totalTicketSupply : felt, userNewSupply : felt){
    let (q, rem) = unsigned_div_rem(totalTicketSupply * 20, 100);
    let is_new_supply_less_than_limit : felt = is_le(userNewSupply, q); 
    if(is_new_supply_less_than_limit == FALSE){
        with_attr error_message("lotusRaffle::maxTicketPurchaseCheck max ticket limit exceed"){
            assert 1 = 0;
        }
        return ();
    }
    return ();
}

func checkIsRefundAvailable{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(raffle_creator : felt, sender : felt, userTicketCount : felt){
    if(raffle_creator == sender){
        return ();
    }
    let is_less_than_zero : felt = is_le(userTicketCount, 0);
    with_attr error_message("lotusRaffle::checkIsRefundAvailable"){
        assert is_less_than_zero = FALSE;
    }
    return ();
}

func onlyWhitelistedCollections{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(collectionAddress : felt){
    let isCollectionVerified : felt = verifiedCollection.read(collectionAddress);
    with_attr error_message("lotusRaffle::onlyWhitelistedCollections collection is not verified"){
        assert isCollectionVerified = TRUE;
    }
    return ();
}


func refundNftIfAvailable{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(is_already_refunded : felt, this : felt, raffle_data: Raffle, raffle_id: felt){
   if(is_already_refunded == FALSE){
        isNftRefunded.write(raffle_id, TRUE);
        transferNft(raffle_data.nftContractAddress, raffle_data.nftTokenId, this, raffle_data.creator);
        return ();
    }
    return ();
}

func transferFund{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(amount : felt, to : felt){
    alloc_locals;
    let _payment_token : felt = payment_token.read();
    let amount_as_uint : Uint256 = felt_to_uint256(amount);
    let (success) = IERC20.transfer(_payment_token, to, amount_as_uint);
    with_attr error_message("lotusRaffle::transferFund fee transfer failed"){
        assert success = TRUE;
    }
    return ();
}

func deductFee{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(ticket_price : felt, total_sold_ticket : felt, raffle_creator : felt) -> (fee_amount : felt){
    alloc_locals;
    let (l_address) = lotus_contract.read();
    let (creator_lotus_balance) = getNftBalance(raffle_creator, l_address);
    let is_lotus_balance_less_than_or_equal_zero : felt = is_le(creator_lotus_balance, 0);
    let total_sold_amount : felt = ticket_price * total_sold_ticket;

    if(is_lotus_balance_less_than_or_equal_zero == FALSE){
        let _rate : felt = fee_rate.read();
        let fee : felt = (total_sold_amount * _rate) / 10000;
        let receiver : felt = fee_address.read();
        transferFund(fee, receiver);
        let _fee_deducted : felt = total_sold_amount - fee;
        return (_fee_deducted,);
    }else{
        return (total_sold_amount,);
    }
}

func transferNft{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(nft_contract :felt, tokenId : Uint256, _from : felt, winner : felt){
    IERC721.transferFrom(nft_contract, _from, winner, tokenId);
    return ();
}

//Conversions

func felt_to_uint256{range_check_ptr}(x) -> (uint_x: Uint256) {
    let (high, low) = split_felt(x);
    return (Uint256(low=low, high=high),);
}

func uint256_to_felt{range_check_ptr}(value: Uint256) -> (value: felt) {
    assert_lt_felt(value.high, 2 ** 123);
    return (value.high * (2 ** 128) + value.low,);
}
