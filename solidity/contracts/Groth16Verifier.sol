
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @notice Supports verifying Groth16 proofs over BLS12-381 using EIP-2537 precompiles.
contract Verifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIR = 0x0f;

    // BLS12-381 scalar field Fr order R.
    uint256 constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X_HI = 18760507465996027437082131503599908401;
    uint256 constant ALPHA_X_LO = 85436195624693551036331182718879740472843948036590846104381615837272427612746;
    uint256 constant ALPHA_Y_HI = 13670989550872807959605632447564754232;
    uint256 constant ALPHA_Y_LO = 105549866086029609995685970815781090192780861296438940404981538440755011360886;

    // Groth16 beta point in G2 (negated)
    uint256 constant BETA_NEG_X_0_HI = 27558900633084989342400157888835527992;
    uint256 constant BETA_NEG_X_0_LO = 64334378196681876632618874278653748606627933767038993319135636872752788694720;
    uint256 constant BETA_NEG_X_1_HI = 34092813977396133157247194413317655293;
    uint256 constant BETA_NEG_X_1_LO = 6365076515724612192986592618547994196437721215661263372736525089218759880043;
    uint256 constant BETA_NEG_Y_0_HI = 27966736390379647478304367486413810416;
    uint256 constant BETA_NEG_Y_0_LO = 98914305133453174290602607494456400067236748787810897195484584922235212012099;
    uint256 constant BETA_NEG_Y_1_HI = 1882826118508568979379034261460955442;
    uint256 constant BETA_NEG_Y_1_LO = 42933282771060812049122292922611292490720325478851820735514646098762027984587;

    // Groth16 gamma point in G2 (negated)
    uint256 constant GAMMA_NEG_X_0_HI = 5775681595877158368637790534800629917;
    uint256 constant GAMMA_NEG_X_0_LO = 8541128873490935383923471909354203076112845413348080104802239641270062319133;
    uint256 constant GAMMA_NEG_X_1_HI = 541731885050154882793116859520886756;
    uint256 constant GAMMA_NEG_X_1_LO = 81282558662438327396114376590357411964509890244306738027053999320069304237368;
    uint256 constant GAMMA_NEG_Y_0_HI = 4508675019479263278107378026036026370;
    uint256 constant GAMMA_NEG_Y_0_LO = 11137549505366729751809017001357085725999745753988618450457019830607180485193;
    uint256 constant GAMMA_NEG_Y_1_HI = 839086857733794996084037824271886761;
    uint256 constant GAMMA_NEG_Y_1_LO = 63442471015741411256092224563643507331746871776956739629001393568013312400357;

    // Groth16 delta point in G2 (negated)
    uint256 constant DELTA_NEG_X_0_HI = 10975878910132669094851239330846027736;
    uint256 constant DELTA_NEG_X_0_LO = 47303456238419232441324380691232589602562431100756159147535740171481482905101;
    uint256 constant DELTA_NEG_X_1_HI = 15712251836951067891793513144581700728;
    uint256 constant DELTA_NEG_X_1_LO = 88362070553610094161696614015441212782327068443471057569728508761647049159325;
    uint256 constant DELTA_NEG_Y_0_HI = 16943802196256406997273225749669835670;
    uint256 constant DELTA_NEG_Y_0_LO = 65925111336683335049081541212532383450926764051086824113154540625473266928965;
    uint256 constant DELTA_NEG_Y_1_HI = 1678121624040700734818205877468685013;
    uint256 constant DELTA_NEG_Y_1_LO = 111047491725566942983909985170903687695110387830838200675918374079304980596478;
    // Pedersen G point in G2
    uint256 constant PEDERSEN_G_X_0_HI = 15957593494711720968207440311963184173;
    uint256 constant PEDERSEN_G_X_0_LO = 103062181875102844199137853104397225196220615118407427234039927895392120346211;
    uint256 constant PEDERSEN_G_X_1_HI = 33254873923776332895720483025378057649;
    uint256 constant PEDERSEN_G_X_1_LO = 95443165189617693421236540137761391549792314575092242642654891374999570187424;
    uint256 constant PEDERSEN_G_Y_0_HI = 16426520036958966177440081102522649186;
    uint256 constant PEDERSEN_G_Y_0_LO = 69257994463152163605864214170369477958007387016336428329465446651713150907318;
    uint256 constant PEDERSEN_G_Y_1_HI = 11895513029633402591189251419468325145;
    uint256 constant PEDERSEN_G_Y_1_LO = 16815931445573213000804155091248483295300926469708733862229485682717803681232;

    // Pedersen GSigmaNeg point in G2
    uint256 constant PEDERSEN_GSIGMANEG_X_0_HI = 15805268891546623907651186359584759730;
    uint256 constant PEDERSEN_GSIGMANEG_X_0_LO = 27002398959731108877360404247431919444780345372072721739961122522565504075901;
    uint256 constant PEDERSEN_GSIGMANEG_X_1_HI = 22134369553334955409063515282361285571;
    uint256 constant PEDERSEN_GSIGMANEG_X_1_LO = 7167835800606267016434089176752098186418278973668214478468253230433697873412;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_HI = 12051308895803181171632377294669158409;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_LO = 85074440715852938105919989826786828679250661525709736148505367815408183552443;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_HI = 31446413831010958094496717680539513608;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_LO = 76445742113022633277887640835630311182908747159830684525475683789615366399404;

    // Constant and public input points
    uint256 constant CONSTANT_X_HI = 4604052481903604733376416300660442737;
    uint256 constant CONSTANT_X_LO = 57940579148448195155794369491976577347566005841701837387612965788531951764671;
    uint256 constant CONSTANT_Y_HI = 21957509668209000818144332735262069056;
    uint256 constant CONSTANT_Y_LO = 80725021988241035218319112973538237123135143849881593135754160823602967120204;
    uint256 constant PUB_0_X_HI = 33899631802206947380618129625469013550;
    uint256 constant PUB_0_X_LO = 13692429773968971888283094223096044996713229321563554638748595731629424194182;
    uint256 constant PUB_0_Y_HI = 20651859171688315491181310883630707061;
    uint256 constant PUB_0_Y_LO = 30162618369317084729887233660005745207989701981690398536444012355735433839142;
    uint256 constant PUB_1_X_HI = 16670065886178041273031131418704829465;
    uint256 constant PUB_1_X_LO = 54561073714816021040020033123989049390130686854202863296310102703722330618014;
    uint256 constant PUB_1_Y_HI = 1310187002949943249603782993803784070;
    uint256 constant PUB_1_Y_LO = 21971071282139505677747213068316212213265752165520744756484800157920040370120;
    uint256 constant PUB_2_X_HI = 4259668531773984815183299777915514265;
    uint256 constant PUB_2_X_LO = 92582702384528337788796806999735703873019237406615033776164138542939320471635;
    uint256 constant PUB_2_Y_HI = 3406915454127207439863434887033776182;
    uint256 constant PUB_2_Y_LO = 56693680736959361007384201391883041613547096629603576463590069714501586423834;
    uint256 constant PUB_3_X_HI = 31721713585134039333322802437878206417;
    uint256 constant PUB_3_X_LO = 5462784012032180670890379773193343898261467638259834069935219540824368179868;
    uint256 constant PUB_3_Y_HI = 33926408337118633051603862949281137532;
    uint256 constant PUB_3_Y_LO = 82852252445446246358395751942051384274230032360315520352256244437937856949170;
    uint256 constant PUB_4_X_HI = 14342772665370625466781074579983757967;
    uint256 constant PUB_4_X_LO = 20656634654534915829747788081077920339118959347340656674457643454517507044976;
    uint256 constant PUB_4_Y_HI = 3996539030635426091440851987219770440;
    uint256 constant PUB_4_Y_LO = 83985594289735636889728127538869915499425564104336075594027688235545973036918;
    uint256 constant PUB_5_X_HI = 15909647185728597956400289986219794625;
    uint256 constant PUB_5_X_LO = 103012344337673334820440536418931323396180866734691798438463209358339251798141;
    uint256 constant PUB_5_Y_HI = 9518122712427365020251714068751922431;
    uint256 constant PUB_5_Y_LO = 17961600180206787498852824482296589458020283629363054480852598734567292335168;
    uint256 constant PUB_6_X_HI = 8678596608181299979505582225641408011;
    uint256 constant PUB_6_X_LO = 29172553940050154207519954192486033714438265606177135008955342107243969997527;
    uint256 constant PUB_6_Y_HI = 16070416525955367689280246598774132131;
    uint256 constant PUB_6_Y_LO = 110257080381689569393725506639895236035112907797989332480239171791347475871756;
    uint256 constant PUB_7_X_HI = 34565203065430915592381133257551544021;
    uint256 constant PUB_7_X_LO = 81896860472291170251361666935947421164527378727744890449685076708146407641633;
    uint256 constant PUB_7_Y_HI = 22869875804403356817425305246161691710;
    uint256 constant PUB_7_Y_LO = 64471643992155997527862318048167699162171525336698817152059523429996394203346;
    uint256 constant PUB_8_X_HI = 11719251053497239735388159205322447954;
    uint256 constant PUB_8_X_LO = 33433094185692294405655310824464405463549813370417014256503090203222154266057;
    uint256 constant PUB_8_Y_HI = 23774628335982486774919978636433006706;
    uint256 constant PUB_8_Y_LO = 50780576970867589312601531827521725650121171578279407105870199299343512109786;
    uint256 constant PUB_9_X_HI = 18692220567319636546605115202581049548;
    uint256 constant PUB_9_X_LO = 107923115305718782666623682186118321818311996520981508505016703908036590792905;
    uint256 constant PUB_9_Y_HI = 34515725383218706193296607847228608950;
    uint256 constant PUB_9_Y_LO = 113377222964344586762048058605280179180658782180251921027575588268334614238208;
    uint256 constant PUB_10_X_HI = 14668818731994780335405396648455814648;
    uint256 constant PUB_10_X_LO = 74225380374990331667233263290848847436126325875566122884345431510365593533669;
    uint256 constant PUB_10_Y_HI = 25098769923170640270544658790416045014;
    uint256 constant PUB_10_Y_LO = 96536206737010657262602714059440278833577543690910103002835588320500498658260;
    uint256 constant PUB_11_X_HI = 6601351294767687914558456007914569747;
    uint256 constant PUB_11_X_LO = 75071589103866810327286483712566344020002346162771933867746545508870168712950;
    uint256 constant PUB_11_Y_HI = 23872599410626004767449651122222150552;
    uint256 constant PUB_11_Y_LO = 64270336518512650759634926944066920134907648326691493757797309512847342822289;
    uint256 constant PUB_12_X_HI = 11454782352304407276608237170328645176;
    uint256 constant PUB_12_X_LO = 46232872487690384375476795402251339562674788278716511953141602415353501908611;
    uint256 constant PUB_12_Y_HI = 6452121348102688375555354509036512916;
    uint256 constant PUB_12_Y_LO = 23079111717319446694471587209409082346315130456795418372633201314151707078402;
    uint256 constant PUB_13_X_HI = 28669733364783798897958198705663256578;
    uint256 constant PUB_13_X_LO = 77437227926309290128864458674334692393995917315466972637969253718196486517588;
    uint256 constant PUB_13_Y_HI = 7506496249182405507738844859451240843;
    uint256 constant PUB_13_Y_LO = 77138789550251032690554494504668889573991177589983084779349117337450460464713;
    uint256 constant PUB_14_X_HI = 33526136946469813179324963337691352039;
    uint256 constant PUB_14_X_LO = 64280991894811112969649244035553322383144158029895851087821662335215810238613;
    uint256 constant PUB_14_Y_HI = 9209026322714728739052821369255215174;
    uint256 constant PUB_14_Y_LO = 9198914170505639813943281773105309236014387183477477104428327205093178834939;
    uint256 constant PUB_15_X_HI = 25384391330567749449766610596056909510;
    uint256 constant PUB_15_X_LO = 27658600790873902095589405057748721812633168617843548281990274784440958130159;
    uint256 constant PUB_15_Y_HI = 4000547864369319319839696095004336275;
    uint256 constant PUB_15_Y_LO = 33063187109263783559634640302603453657345733825391752914617186227320815952833;
    uint256 constant PUB_16_X_HI = 31040639631687538513454619335177723648;
    uint256 constant PUB_16_X_LO = 112308223154142395614375661286491359074902930634353016854932140606947130441910;
    uint256 constant PUB_16_Y_HI = 29669607117052252256996971294013107716;
    uint256 constant PUB_16_Y_LO = 32450850634961274132403656993116240945952786938918493353735301291295386245010;
    uint256 constant PUB_17_X_HI = 22138727842045235975413510641687012885;
    uint256 constant PUB_17_X_LO = 45284830265609071161425769223722812352110232041883379335213826419406743794598;
    uint256 constant PUB_17_Y_HI = 13801365400394934091113915538800000395;
    uint256 constant PUB_17_Y_LO = 115637475556539142589522320228235649342555008639935114617689467193800393433748;
    uint256 constant PUB_18_X_HI = 2854683832248254404335162699469775278;
    uint256 constant PUB_18_X_LO = 22350854114887394373726977142982160568763883821222955636823240881698146148902;
    uint256 constant PUB_18_Y_HI = 22438752841529723353806119417691105465;
    uint256 constant PUB_18_Y_LO = 23045887719429829607846769201183641377351224318361351299266262779093085393221;
    uint256 constant PUB_19_X_HI = 29758484380616341906226276799961453730;
    uint256 constant PUB_19_X_LO = 115173732503734187112201528956901132288228323813018573446480414472848872573257;
    uint256 constant PUB_19_Y_HI = 5772573486058460454008981081317749768;
    uint256 constant PUB_19_Y_LO = 71686940956539788911060858369763765238881708434544320599213882768080119990051;
    uint256 constant PUB_20_X_HI = 20408051982909591083294133981933660818;
    uint256 constant PUB_20_X_LO = 91536692067705074363993399215153108987224905114413299372105220400569301147273;
    uint256 constant PUB_20_Y_HI = 18426276246583774431451048369189240368;
    uint256 constant PUB_20_Y_LO = 108122717545273010637059189622604465108121298008315289646541286466267740027430;
    uint256 constant PUB_21_X_HI = 11449529961998248657711709755628714748;
    uint256 constant PUB_21_X_LO = 104013283828389313852092747993675072925565981389379373490920728516948350561427;
    uint256 constant PUB_21_Y_HI = 27780583622251875345487568866492500316;
    uint256 constant PUB_21_Y_LO = 62553087265140179741703576642699686350796518398020846851414964503320372329545;
    uint256 constant PUB_22_X_HI = 15714555308839909145755085818678527780;
    uint256 constant PUB_22_X_LO = 51799612285949414002759083791680190512418434194442101450863382307717254815955;
    uint256 constant PUB_22_Y_HI = 25658947116415028655248314476470810192;
    uint256 constant PUB_22_Y_LO = 69688859124828659836795323328333214438271919871167610122448720727441869816905;
    uint256 constant PUB_23_X_HI = 2423375208460591584428223224025348573;
    uint256 constant PUB_23_X_LO = 29479015239544060354583242211142243113997940016387423506798782180678648244729;
    uint256 constant PUB_23_Y_HI = 31011030281039712350133272135498609772;
    uint256 constant PUB_23_Y_LO = 82204583090196865805868467240899047360442135795881093846964739228683926166289;
    uint256 constant PUB_24_X_HI = 23063066764110241564263666509588117185;
    uint256 constant PUB_24_X_LO = 111200041655950836544577262823663223226970794054528986520598599838352245056873;
    uint256 constant PUB_24_Y_HI = 9114146310930245832356435862024447707;
    uint256 constant PUB_24_Y_LO = 14638966374813408554030925015113259420910978180505068085774538794774902253158;
    uint256 constant PUB_25_X_HI = 4206637687158234945738456525947240853;
    uint256 constant PUB_25_X_LO = 98240456531778404494552145521445936878098565554786272175259101991163574985113;
    uint256 constant PUB_25_Y_HI = 6303841948374931413369939366311376966;
    uint256 constant PUB_25_Y_LO = 88659407763743963909156148010930087975196039585925568124343418525373961822565;
    uint256 constant PUB_26_X_HI = 17599944364395486765294185517312137397;
    uint256 constant PUB_26_X_LO = 29326797902512370717418540724231971214436963766535634918049522857600272842278;
    uint256 constant PUB_26_Y_HI = 33723128157427461541939465887508958323;
    uint256 constant PUB_26_Y_LO = 108124985377955643593095473769939946488156193893544735442792197747423548574070;
    uint256 constant PUB_27_X_HI = 33561404314441197668147874990466267644;
    uint256 constant PUB_27_X_LO = 39879159949935560428952026137615691630638315236413734456440436181256973942662;
    uint256 constant PUB_27_Y_HI = 33610853471467128696977116450263973065;
    uint256 constant PUB_27_Y_LO = 23359167023526885134218736412184648007279659629303705425976914853486892754893;
    uint256 constant PUB_28_X_HI = 34175893061546978080067873266012408803;
    uint256 constant PUB_28_X_LO = 34661179771032690560359360013657759171500995235085170667707303226884659685089;
    uint256 constant PUB_28_Y_HI = 14713095329871164130882966825934493731;
    uint256 constant PUB_28_Y_LO = 57662211765873549987645000090459014753085174354668143104336018383247922822117;
    uint256 constant PUB_29_X_HI = 30725606104222206280559743446666668009;
    uint256 constant PUB_29_X_LO = 82377780720251533258695446700848007999452598024394972566193814204884998698478;
    uint256 constant PUB_29_Y_HI = 28804468100025086273819229035747572963;
    uint256 constant PUB_29_Y_LO = 79136107123728431907256911793017500664193835623313095788687237820026857933563;
    uint256 constant PUB_30_X_HI = 5850890819463842974475458970643682293;
    uint256 constant PUB_30_X_LO = 106642355885174879170396268932701736412231156611220722704408844074281145795499;
    uint256 constant PUB_30_Y_HI = 8271576084847290734365380290211589952;
    uint256 constant PUB_30_Y_LO = 102728625108629875421367122391506637335401714576672754644724414553427490653412;

    /// Compute the public input linear combination.
    /// @notice Uses BLS12-381 G1 MSM precompile (EIP-2537) for efficient computation.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof (padded to 128 bytes each).
    /// @return x_hi The high part of the X coordinate of the resulting G1 point.
    /// @return x_lo The low part of the X coordinate.
    /// @return y_hi The high part of the Y coordinate.
    /// @return y_lo The low part of the Y coordinate.
    function publicInputMSM(
        uint256[30] calldata input,
        uint256[1] memory publicCommitments,
        uint256[4] memory commitments
    )
    internal view returns (uint256 x_hi, uint256 x_lo, uint256 y_hi, uint256 y_lo) {
        // BLS12_G1MSM input: k elements of (G1_point[128 bytes] + scalar[32 bytes]) = k * 160 bytes
        // Output: one G1 point (128 bytes)
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let s
            // Element 0: CONSTANT with scalar 1
            mstore(f, CONSTANT_X_HI)
            mstore(add(f, 0x20), CONSTANT_X_LO)
            mstore(add(f, 0x40), CONSTANT_Y_HI)
            mstore(add(f, 0x60), CONSTANT_Y_LO)
            mstore(add(f, 0x80), 1)
            // Element 1: PUB_0
            mstore(add(f, 0xa0), PUB_0_X_HI)
            mstore(add(f, 0xc0), PUB_0_X_LO)
            mstore(add(f, 0xe0), PUB_0_Y_HI)
            mstore(add(f, 0x100), PUB_0_Y_LO)
            s := calldataload(input)
            mstore(add(f, 0x120), s)
            success := and(success, lt(s, R))
            // Element 2: PUB_1
            mstore(add(f, 0x140), PUB_1_X_HI)
            mstore(add(f, 0x160), PUB_1_X_LO)
            mstore(add(f, 0x180), PUB_1_Y_HI)
            mstore(add(f, 0x1a0), PUB_1_Y_LO)
            s := calldataload(add(input, 0x20))
            mstore(add(f, 0x1c0), s)
            success := and(success, lt(s, R))
            // Element 3: PUB_2
            mstore(add(f, 0x1e0), PUB_2_X_HI)
            mstore(add(f, 0x200), PUB_2_X_LO)
            mstore(add(f, 0x220), PUB_2_Y_HI)
            mstore(add(f, 0x240), PUB_2_Y_LO)
            s := calldataload(add(input, 0x40))
            mstore(add(f, 0x260), s)
            success := and(success, lt(s, R))
            // Element 4: PUB_3
            mstore(add(f, 0x280), PUB_3_X_HI)
            mstore(add(f, 0x2a0), PUB_3_X_LO)
            mstore(add(f, 0x2c0), PUB_3_Y_HI)
            mstore(add(f, 0x2e0), PUB_3_Y_LO)
            s := calldataload(add(input, 0x60))
            mstore(add(f, 0x300), s)
            success := and(success, lt(s, R))
            // Element 5: PUB_4
            mstore(add(f, 0x320), PUB_4_X_HI)
            mstore(add(f, 0x340), PUB_4_X_LO)
            mstore(add(f, 0x360), PUB_4_Y_HI)
            mstore(add(f, 0x380), PUB_4_Y_LO)
            s := calldataload(add(input, 0x80))
            mstore(add(f, 0x3a0), s)
            success := and(success, lt(s, R))
            // Element 6: PUB_5
            mstore(add(f, 0x3c0), PUB_5_X_HI)
            mstore(add(f, 0x3e0), PUB_5_X_LO)
            mstore(add(f, 0x400), PUB_5_Y_HI)
            mstore(add(f, 0x420), PUB_5_Y_LO)
            s := calldataload(add(input, 0xa0))
            mstore(add(f, 0x440), s)
            success := and(success, lt(s, R))
            // Element 7: PUB_6
            mstore(add(f, 0x460), PUB_6_X_HI)
            mstore(add(f, 0x480), PUB_6_X_LO)
            mstore(add(f, 0x4a0), PUB_6_Y_HI)
            mstore(add(f, 0x4c0), PUB_6_Y_LO)
            s := calldataload(add(input, 0xc0))
            mstore(add(f, 0x4e0), s)
            success := and(success, lt(s, R))
            // Element 8: PUB_7
            mstore(add(f, 0x500), PUB_7_X_HI)
            mstore(add(f, 0x520), PUB_7_X_LO)
            mstore(add(f, 0x540), PUB_7_Y_HI)
            mstore(add(f, 0x560), PUB_7_Y_LO)
            s := calldataload(add(input, 0xe0))
            mstore(add(f, 0x580), s)
            success := and(success, lt(s, R))
            // Element 9: PUB_8
            mstore(add(f, 0x5a0), PUB_8_X_HI)
            mstore(add(f, 0x5c0), PUB_8_X_LO)
            mstore(add(f, 0x5e0), PUB_8_Y_HI)
            mstore(add(f, 0x600), PUB_8_Y_LO)
            s := calldataload(add(input, 0x100))
            mstore(add(f, 0x620), s)
            success := and(success, lt(s, R))
            // Element 10: PUB_9
            mstore(add(f, 0x640), PUB_9_X_HI)
            mstore(add(f, 0x660), PUB_9_X_LO)
            mstore(add(f, 0x680), PUB_9_Y_HI)
            mstore(add(f, 0x6a0), PUB_9_Y_LO)
            s := calldataload(add(input, 0x120))
            mstore(add(f, 0x6c0), s)
            success := and(success, lt(s, R))
            // Element 11: PUB_10
            mstore(add(f, 0x6e0), PUB_10_X_HI)
            mstore(add(f, 0x700), PUB_10_X_LO)
            mstore(add(f, 0x720), PUB_10_Y_HI)
            mstore(add(f, 0x740), PUB_10_Y_LO)
            s := calldataload(add(input, 0x140))
            mstore(add(f, 0x760), s)
            success := and(success, lt(s, R))
            // Element 12: PUB_11
            mstore(add(f, 0x780), PUB_11_X_HI)
            mstore(add(f, 0x7a0), PUB_11_X_LO)
            mstore(add(f, 0x7c0), PUB_11_Y_HI)
            mstore(add(f, 0x7e0), PUB_11_Y_LO)
            s := calldataload(add(input, 0x160))
            mstore(add(f, 0x800), s)
            success := and(success, lt(s, R))
            // Element 13: PUB_12
            mstore(add(f, 0x820), PUB_12_X_HI)
            mstore(add(f, 0x840), PUB_12_X_LO)
            mstore(add(f, 0x860), PUB_12_Y_HI)
            mstore(add(f, 0x880), PUB_12_Y_LO)
            s := calldataload(add(input, 0x180))
            mstore(add(f, 0x8a0), s)
            success := and(success, lt(s, R))
            // Element 14: PUB_13
            mstore(add(f, 0x8c0), PUB_13_X_HI)
            mstore(add(f, 0x8e0), PUB_13_X_LO)
            mstore(add(f, 0x900), PUB_13_Y_HI)
            mstore(add(f, 0x920), PUB_13_Y_LO)
            s := calldataload(add(input, 0x1a0))
            mstore(add(f, 0x940), s)
            success := and(success, lt(s, R))
            // Element 15: PUB_14
            mstore(add(f, 0x960), PUB_14_X_HI)
            mstore(add(f, 0x980), PUB_14_X_LO)
            mstore(add(f, 0x9a0), PUB_14_Y_HI)
            mstore(add(f, 0x9c0), PUB_14_Y_LO)
            s := calldataload(add(input, 0x1c0))
            mstore(add(f, 0x9e0), s)
            success := and(success, lt(s, R))
            // Element 16: PUB_15
            mstore(add(f, 0xa00), PUB_15_X_HI)
            mstore(add(f, 0xa20), PUB_15_X_LO)
            mstore(add(f, 0xa40), PUB_15_Y_HI)
            mstore(add(f, 0xa60), PUB_15_Y_LO)
            s := calldataload(add(input, 0x1e0))
            mstore(add(f, 0xa80), s)
            success := and(success, lt(s, R))
            // Element 17: PUB_16
            mstore(add(f, 0xaa0), PUB_16_X_HI)
            mstore(add(f, 0xac0), PUB_16_X_LO)
            mstore(add(f, 0xae0), PUB_16_Y_HI)
            mstore(add(f, 0xb00), PUB_16_Y_LO)
            s := calldataload(add(input, 0x200))
            mstore(add(f, 0xb20), s)
            success := and(success, lt(s, R))
            // Element 18: PUB_17
            mstore(add(f, 0xb40), PUB_17_X_HI)
            mstore(add(f, 0xb60), PUB_17_X_LO)
            mstore(add(f, 0xb80), PUB_17_Y_HI)
            mstore(add(f, 0xba0), PUB_17_Y_LO)
            s := calldataload(add(input, 0x220))
            mstore(add(f, 0xbc0), s)
            success := and(success, lt(s, R))
            // Element 19: PUB_18
            mstore(add(f, 0xbe0), PUB_18_X_HI)
            mstore(add(f, 0xc00), PUB_18_X_LO)
            mstore(add(f, 0xc20), PUB_18_Y_HI)
            mstore(add(f, 0xc40), PUB_18_Y_LO)
            s := calldataload(add(input, 0x240))
            mstore(add(f, 0xc60), s)
            success := and(success, lt(s, R))
            // Element 20: PUB_19
            mstore(add(f, 0xc80), PUB_19_X_HI)
            mstore(add(f, 0xca0), PUB_19_X_LO)
            mstore(add(f, 0xcc0), PUB_19_Y_HI)
            mstore(add(f, 0xce0), PUB_19_Y_LO)
            s := calldataload(add(input, 0x260))
            mstore(add(f, 0xd00), s)
            success := and(success, lt(s, R))
            // Element 21: PUB_20
            mstore(add(f, 0xd20), PUB_20_X_HI)
            mstore(add(f, 0xd40), PUB_20_X_LO)
            mstore(add(f, 0xd60), PUB_20_Y_HI)
            mstore(add(f, 0xd80), PUB_20_Y_LO)
            s := calldataload(add(input, 0x280))
            mstore(add(f, 0xda0), s)
            success := and(success, lt(s, R))
            // Element 22: PUB_21
            mstore(add(f, 0xdc0), PUB_21_X_HI)
            mstore(add(f, 0xde0), PUB_21_X_LO)
            mstore(add(f, 0xe00), PUB_21_Y_HI)
            mstore(add(f, 0xe20), PUB_21_Y_LO)
            s := calldataload(add(input, 0x2a0))
            mstore(add(f, 0xe40), s)
            success := and(success, lt(s, R))
            // Element 23: PUB_22
            mstore(add(f, 0xe60), PUB_22_X_HI)
            mstore(add(f, 0xe80), PUB_22_X_LO)
            mstore(add(f, 0xea0), PUB_22_Y_HI)
            mstore(add(f, 0xec0), PUB_22_Y_LO)
            s := calldataload(add(input, 0x2c0))
            mstore(add(f, 0xee0), s)
            success := and(success, lt(s, R))
            // Element 24: PUB_23
            mstore(add(f, 0xf00), PUB_23_X_HI)
            mstore(add(f, 0xf20), PUB_23_X_LO)
            mstore(add(f, 0xf40), PUB_23_Y_HI)
            mstore(add(f, 0xf60), PUB_23_Y_LO)
            s := calldataload(add(input, 0x2e0))
            mstore(add(f, 0xf80), s)
            success := and(success, lt(s, R))
            // Element 25: PUB_24
            mstore(add(f, 0xfa0), PUB_24_X_HI)
            mstore(add(f, 0xfc0), PUB_24_X_LO)
            mstore(add(f, 0xfe0), PUB_24_Y_HI)
            mstore(add(f, 0x1000), PUB_24_Y_LO)
            s := calldataload(add(input, 0x300))
            mstore(add(f, 0x1020), s)
            success := and(success, lt(s, R))
            // Element 26: PUB_25
            mstore(add(f, 0x1040), PUB_25_X_HI)
            mstore(add(f, 0x1060), PUB_25_X_LO)
            mstore(add(f, 0x1080), PUB_25_Y_HI)
            mstore(add(f, 0x10a0), PUB_25_Y_LO)
            s := calldataload(add(input, 0x320))
            mstore(add(f, 0x10c0), s)
            success := and(success, lt(s, R))
            // Element 27: PUB_26
            mstore(add(f, 0x10e0), PUB_26_X_HI)
            mstore(add(f, 0x1100), PUB_26_X_LO)
            mstore(add(f, 0x1120), PUB_26_Y_HI)
            mstore(add(f, 0x1140), PUB_26_Y_LO)
            s := calldataload(add(input, 0x340))
            mstore(add(f, 0x1160), s)
            success := and(success, lt(s, R))
            // Element 28: PUB_27
            mstore(add(f, 0x1180), PUB_27_X_HI)
            mstore(add(f, 0x11a0), PUB_27_X_LO)
            mstore(add(f, 0x11c0), PUB_27_Y_HI)
            mstore(add(f, 0x11e0), PUB_27_Y_LO)
            s := calldataload(add(input, 0x360))
            mstore(add(f, 0x1200), s)
            success := and(success, lt(s, R))
            // Element 29: PUB_28
            mstore(add(f, 0x1220), PUB_28_X_HI)
            mstore(add(f, 0x1240), PUB_28_X_LO)
            mstore(add(f, 0x1260), PUB_28_Y_HI)
            mstore(add(f, 0x1280), PUB_28_Y_LO)
            s := calldataload(add(input, 0x380))
            mstore(add(f, 0x12a0), s)
            success := and(success, lt(s, R))
            // Element 30: PUB_29
            mstore(add(f, 0x12c0), PUB_29_X_HI)
            mstore(add(f, 0x12e0), PUB_29_X_LO)
            mstore(add(f, 0x1300), PUB_29_Y_HI)
            mstore(add(f, 0x1320), PUB_29_Y_LO)
            s := calldataload(add(input, 0x3a0))
            mstore(add(f, 0x1340), s)
            success := and(success, lt(s, R))
            // Element 31: PUB_30
            mstore(add(f, 0x1360), PUB_30_X_HI)
            mstore(add(f, 0x1380), PUB_30_X_LO)
            mstore(add(f, 0x13a0), PUB_30_Y_HI)
            mstore(add(f, 0x13c0), PUB_30_Y_LO)
            s := mload(publicCommitments)
            mstore(add(f, 0x13e0), s)
            success := and(success, lt(s, R))
            // Add commitment G1 points with scalar 1
            // Commitments are stored in memory as padded 128-byte G1 points (4 uint256 each)
            mstore(add(f, 0x1400), mload(add(commitments, 0x0)))
            mstore(add(f, 0x1420), mload(add(commitments, 0x20)))
            mstore(add(f, 0x1440), mload(add(commitments, 0x40)))
            mstore(add(f, 0x1460), mload(add(commitments, 0x60)))
            mstore(add(f, 0x1480), 1)

            success := and(success, staticcall(gas(), PRECOMPILE_BLS12_G1MSM, f, 0x14a0, f, 0x80))

            x_hi := mload(f)
            x_lo := mload(add(f, 0x20))
            y_hi := mload(add(f, 0x40))
            y_lo := mload(add(f, 0x60))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the serialized proof, containing Ar (96 bytes G1), Bs (192 bytes G2),
    /// Krs (96 bytes G1) = 384 bytes total.
    /// Followed by commitments (1 × 96 bytes G1) and commitmentPok (96 bytes G1).
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        bytes calldata proof,
        uint256[30] calldata input
    ) public view {
        require(proof.length == 576, "invalid proof length");
        // Load commitment points and compute public commitment hashes
        uint256[1] memory publicCommitments;
        uint256[4] memory commitments;

        // Load commitment points from proof (padded to 128 bytes each in memory)
        assembly ("memory-safe") {
            // Commitment 0: load raw 96-byte G1 from calldata, pad to 128 bytes
            mstore(add(commitments, 0x0), 0)
            calldatacopy(add(commitments, 0x10), add(proof.offset, 0x180), 0x30)
            mstore(add(commitments, 0x40), 0)
            calldatacopy(add(commitments, 0x50), add(proof.offset, 0x1b0), 0x30)
        }

        // Compute public commitment hashes
        uint256[] memory publicAndCommitmentCommitted;
        publicAndCommitmentCommitted = new uint256[](24);
        assembly ("memory-safe") {
            let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
            calldatacopy(add(publicAndCommitmentCommittedOffset, 0), add(input, 160), 384)
            calldatacopy(add(publicAndCommitmentCommittedOffset, 384), add(input, 576), 384)
        }

        // Hash: keccak256(commitment_raw_bytes || publicAndCommitmentCommitted) % R
        // The commitment raw bytes are 96 bytes from calldata
        {
            bytes memory hashInput = abi.encodePacked(
                proof[384:480],
                publicAndCommitmentCommitted
            );
            publicCommitments[0] = uint256(keccak256(hashInput)) % R;
        }

        // Verify Pedersen commitments
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(commitment, GSigmaNeg)
            // Load commitment G1 point (already padded in commitments memory)
            mcopy(f, commitments, 0x80)
            // GSigmaNeg G2 point
            mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_X_0_HI)
            mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_X_0_LO)
            mstore(add(f, 0xc0), PEDERSEN_GSIGMANEG_X_1_HI)
            mstore(add(f, 0xe0), PEDERSEN_GSIGMANEG_X_1_LO)
            mstore(add(f, 0x100), PEDERSEN_GSIGMANEG_Y_0_HI)
            mstore(add(f, 0x120), PEDERSEN_GSIGMANEG_Y_0_LO)
            mstore(add(f, 0x140), PEDERSEN_GSIGMANEG_Y_1_HI)
            mstore(add(f, 0x160), PEDERSEN_GSIGMANEG_Y_1_LO)

            // Pair 1: e(Pok, G)
            // Load PoK from proof calldata (96 bytes at offset after commitments)
            mstore(add(f, 0x180), 0)
            calldatacopy(add(f, 0x190), add(proof.offset, 0x1e0), 0x30)
            mstore(add(f, 0x1c0), 0)
            calldatacopy(add(f, 0x1d0), add(proof.offset, 0x210), 0x30)
            // G point
            mstore(add(f, 0x200), PEDERSEN_G_X_0_HI)
            mstore(add(f, 0x220), PEDERSEN_G_X_0_LO)
            mstore(add(f, 0x240), PEDERSEN_G_X_1_HI)
            mstore(add(f, 0x260), PEDERSEN_G_X_1_LO)
            mstore(add(f, 0x280), PEDERSEN_G_Y_0_HI)
            mstore(add(f, 0x2a0), PEDERSEN_G_Y_0_LO)
            mstore(add(f, 0x2c0), PEDERSEN_G_Y_1_HI)
            mstore(add(f, 0x2e0), PEDERSEN_G_Y_1_LO)

            // BLS12_PAIR: 2 pairs × 384 bytes = 768 bytes
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x300, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            revert CommitmentInvalid();
        }

        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );

        // Verify the Groth16 pairing equation:
        // e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
        //
        // Pairing input: 4 pairs × (G1[128] + G2[256]) = 4 × 384 = 1536 bytes
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(A, B)
            // A (G1): 96 bytes at proof offset 0x00
            mstore(f, 0)
            calldatacopy(add(f, 0x10), proof.offset, 0x30)
            mstore(add(f, 0x40), 0)
            calldatacopy(add(f, 0x50), add(proof.offset, 0x30), 0x30)
            // B (G2): 192 bytes at proof offset 0x60
            // gnark-crypto serializes G2 as (A1, A0, A1, A0) but EIP-2537 expects (A0, A1, A0, A1)
            // X.A0 (at proof offset 0x90, 2nd component in gnark-crypto serialization)
            mstore(add(f, 0x80), 0)
            calldatacopy(add(f, 0x90), add(proof.offset, 0x90), 0x30)
            // X.A1 (at proof offset 0x60, 1st component in gnark-crypto serialization)
            mstore(add(f, 0xc0), 0)
            calldatacopy(add(f, 0xd0), add(proof.offset, 0x60), 0x30)
            // Y.A0 (at proof offset 0xf0, 4th component in gnark-crypto serialization)
            mstore(add(f, 0x100), 0)
            calldatacopy(add(f, 0x110), add(proof.offset, 0xf0), 0x30)
            // Y.A1 (at proof offset 0xc0, 3rd component in gnark-crypto serialization)
            mstore(add(f, 0x140), 0)
            calldatacopy(add(f, 0x150), add(proof.offset, 0xc0), 0x30)

            // Pair 1: e(C, -δ)
            // C (G1): 96 bytes at proof offset 0x120
            mstore(add(f, 0x180), 0)
            calldatacopy(add(f, 0x190), add(proof.offset, 0x120), 0x30)
            mstore(add(f, 0x1c0), 0)
            calldatacopy(add(f, 0x1d0), add(proof.offset, 0x150), 0x30)
            // -δ (constant G2)
            mstore(add(f, 0x200), DELTA_NEG_X_0_HI)
            mstore(add(f, 0x220), DELTA_NEG_X_0_LO)
            mstore(add(f, 0x240), DELTA_NEG_X_1_HI)
            mstore(add(f, 0x260), DELTA_NEG_X_1_LO)
            mstore(add(f, 0x280), DELTA_NEG_Y_0_HI)
            mstore(add(f, 0x2a0), DELTA_NEG_Y_0_LO)
            mstore(add(f, 0x2c0), DELTA_NEG_Y_1_HI)
            mstore(add(f, 0x2e0), DELTA_NEG_Y_1_LO)

            // Pair 2: e(α, -β)
            mstore(add(f, 0x300), ALPHA_X_HI)
            mstore(add(f, 0x320), ALPHA_X_LO)
            mstore(add(f, 0x340), ALPHA_Y_HI)
            mstore(add(f, 0x360), ALPHA_Y_LO)
            mstore(add(f, 0x380), BETA_NEG_X_0_HI)
            mstore(add(f, 0x3a0), BETA_NEG_X_0_LO)
            mstore(add(f, 0x3c0), BETA_NEG_X_1_HI)
            mstore(add(f, 0x3e0), BETA_NEG_X_1_LO)
            mstore(add(f, 0x400), BETA_NEG_Y_0_HI)
            mstore(add(f, 0x420), BETA_NEG_Y_0_LO)
            mstore(add(f, 0x440), BETA_NEG_Y_1_HI)
            mstore(add(f, 0x460), BETA_NEG_Y_1_LO)

            // Pair 3: e(L_pub, -γ)
            mstore(add(f, 0x480), Lx_hi)
            mstore(add(f, 0x4a0), Lx_lo)
            mstore(add(f, 0x4c0), Ly_hi)
            mstore(add(f, 0x4e0), Ly_lo)
            mstore(add(f, 0x500), GAMMA_NEG_X_0_HI)
            mstore(add(f, 0x520), GAMMA_NEG_X_0_LO)
            mstore(add(f, 0x540), GAMMA_NEG_X_1_HI)
            mstore(add(f, 0x560), GAMMA_NEG_X_1_LO)
            mstore(add(f, 0x580), GAMMA_NEG_Y_0_HI)
            mstore(add(f, 0x5a0), GAMMA_NEG_Y_0_LO)
            mstore(add(f, 0x5c0), GAMMA_NEG_Y_1_HI)
            mstore(add(f, 0x5e0), GAMMA_NEG_Y_1_LO)

            // BLS12_PAIR: 4 pairs × 384 bytes = 1536 bytes
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
