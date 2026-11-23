// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 4259186599966196336126136993005342757147818429707713503271072703347908818579;
    uint256 constant alphay  = 7497464838667566900432523363633589077123070471062747276007015866064717441657;
    uint256 constant betax1  = 18492434014142354492942376864298248809094643598112740387342446729738454612499;
    uint256 constant betax2  = 8645976226645811223017193873843519159914890995959231749362450855719363167843;
    uint256 constant betay1  = 16054747075223817225460994601459134530370062265225176493932140681094858027679;
    uint256 constant betay2  = 14698076074621953343145540886273721458076855621848137807020037479662862515804;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 20988925871225729056475757005821522532132351394602250679739392304459821104373;
    uint256 constant deltax2 = 3763143265360074126659859227478121509864372983559054087734626276315724434375;
    uint256 constant deltay1 = 12589341625298475488552635186084412670501501772588741871641820933103600491826;
    uint256 constant deltay2 = 17486314688135301022327868881699213952088977005863684179601045166894434757683;

    
    uint256 constant IC0x = 18299322005531628192632762141550719041351427028689588394451237491016830838914;
    uint256 constant IC0y = 15601612863844269213049646347066972999413714845079382252963369935943272342219;
    
    uint256 constant IC1x = 19884870124246624731369663080418353359749862434367627094317739404882023972906;
    uint256 constant IC1y = 8359184362229761298574612638876232646716353540689183064401036363875244268221;
    
    uint256 constant IC2x = 12012704516063929304536018893951490657662780831553686738221062595850432948421;
    uint256 constant IC2y = 478459814593776705796650695724645252182714349818772069258742047779568123772;
    
    uint256 constant IC3x = 7171130211590760736006771005040364938298781776379463341363156059966827614499;
    uint256 constant IC3y = 9147452981525357148388579585401700110025972771115439792977951381329798588359;
    
    uint256 constant IC4x = 14140364516532151401261458273001484312892128561989048831058371587891227274683;
    uint256 constant IC4y = 8483954338232310354848881254157919233301129073867545092919222551220929007859;
    
    uint256 constant IC5x = 1906074830278638018756125331552519450863366369634338650071699223628927108584;
    uint256 constant IC5y = 929168382178049229601046226368063133596789683096454805151105631721146381476;
    
    uint256 constant IC6x = 13475865765229400632423789859830501930786426100518544029584381869664116688571;
    uint256 constant IC6y = 9121951524416558878622276850466011991512842273938907941723353100678506576633;
    
    uint256 constant IC7x = 16617365715778167731579228629546838984034305309676340884717477449084166467932;
    uint256 constant IC7y = 17940745496934894519194312335578712267856645379677749541693340210806530380318;
    
    uint256 constant IC8x = 11728995600468497743494052201048468786067625448866870653318417967423450754151;
    uint256 constant IC8y = 5626862383636107580556666872374300381206326329901770987001243401230234064102;
    
    uint256 constant IC9x = 16680773838553071455944955539550200908848672251763278285229963328772496126926;
    uint256 constant IC9y = 2636320274190771564789053454821170878934146052612861264526500990758878167816;
    
    uint256 constant IC10x = 13490593553729335788421361843338041286904992009173715175988743189041754167268;
    uint256 constant IC10y = 15512237873074036756706081707230209555425034463515288930653650291820069927671;
    
    uint256 constant IC11x = 11981780457160991157423677590060911959381887196571547640767515575547307494416;
    uint256 constant IC11y = 8808435975878136354825437300764724011272248543312314286245734855418810488071;
    
    uint256 constant IC12x = 1923161731565568811698341494256624565853438931862101261140850505050558958354;
    uint256 constant IC12y = 12707635345420141706742302878233703533271724763846255819420879451891874177599;
    
    uint256 constant IC13x = 21175158002813808740695404071622902649386875401690534576488199318061254550975;
    uint256 constant IC13y = 12241007879317282585031823341731270262996491282015693030002471525070671077514;
    
    uint256 constant IC14x = 17882479181288554290360758870981022955798187275621203914696784689455366528203;
    uint256 constant IC14y = 20283496462865050313908460830998705799572522381586938402206757722769239384684;
    
    uint256 constant IC15x = 9680930624802202537562476202786119881817987416667978707635965167945537325743;
    uint256 constant IC15y = 13272221951735386337602736736060107525865835652504624549424770341904539076706;
    
    uint256 constant IC16x = 15765174389756009699771928046853964494546288589869680455123956616091549283084;
    uint256 constant IC16y = 19799776621276794130789101112299913422001908289155917088398953263314498101329;
    
    uint256 constant IC17x = 4327272190723872477764157169698089081415838956789738526216199270408635611129;
    uint256 constant IC17y = 21349668969486319263968467056198939264423316177059059849829214009824662973293;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[17] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
