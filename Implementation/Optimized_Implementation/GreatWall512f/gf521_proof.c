#include "gf521_proof.h"

void qs_gf521_load_witness(
    const quicksilver_state* state, qs_gf521_bits* out, size_t bit_offset)
{
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        out->bit[bit] = quicksilver_get_witness_vec(state, bit_offset + bit);
    }
}

void qs_gf521_load_constant(
    const quicksilver_state* state, qs_gf521_bits* out,
    const uint64_t words[BLOCK521_WORDS])
{
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        const uint8_t value = (words[bit >> 6] >> (bit & 63)) & 1;
        out->bit[bit] = value
            ? quicksilver_one_gf2(state)
            : quicksilver_zero_gf2();
    }
}

void qs_gf521_add(
    const quicksilver_state* state, qs_gf521_bits* out,
    const qs_gf521_bits* x, const qs_gf521_bits* y)
{
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        out->bit[bit] = quicksilver_add_gf2(state, x->bit[bit], y->bit[bit]);
    }
}

void qs_gf521_matmul(
    const quicksilver_state* state, qs_gf521_bits* out,
    const uint64_t matrix[BLOCK521_BITS][BLOCK521_WORDS],
    const qs_gf521_bits* in)
{
    for (size_t row = 0; row < BLOCK521_BITS; ++row) {

        const uint8_t* row_bytes = (const uint8_t*)matrix[row];
        quicksilver_vec_gf2 acc = quicksilver_const_gf2(state, poly1_load(0, 0));
        for (size_t col = 0; col < BLOCK521_BITS; ++col) {
            const poly1_vec coefficient = poly1_load(row_bytes[col / 8], col % 8);
            acc = quicksilver_add_gf2(
                state, acc, quicksilver_mul_const_gf2(state, in->bit[col], coefficient));
        }
        out->bit[row] = acc;
    }
}

static inline quicksilver_vec_gf2 qs_gf521_copy_bit(
    const quicksilver_state* state, const quicksilver_vec_gf2* in)
{
    quicksilver_vec_gf2 out;
    out.mac = in->mac;
    out.value = state->verifier ? 0 : in->value;
    return out;
}

static inline quicksilver_vec_gf2 qs_gf521_xor_bits(
    const quicksilver_state* state,
    const quicksilver_vec_gf2* a, const quicksilver_vec_gf2* b)
{
    quicksilver_vec_gf2 out;
    out.mac = poly_secpar_add(a->mac, b->mac);
    out.value = state->verifier ? 0 : a->value ^ b->value;
    return out;
}

static void qs_gf521_square_noalias(
    const quicksilver_state* state, qs_gf521_bits* restrict out,
    const qs_gf521_bits* restrict in)
{

    out->bit[0] = qs_gf521_xor_bits(state, &in->bit[0], &in->bit[505]);
    out->bit[1] = qs_gf521_copy_bit(state, &in->bit[261]);
    out->bit[2] = qs_gf521_xor_bits(state, &in->bit[1], &in->bit[506]);
    out->bit[3] = qs_gf521_copy_bit(state, &in->bit[262]);
    out->bit[4] = qs_gf521_xor_bits(state, &in->bit[2], &in->bit[507]);
    out->bit[5] = qs_gf521_copy_bit(state, &in->bit[263]);
    out->bit[6] = qs_gf521_xor_bits(state, &in->bit[3], &in->bit[508]);
    out->bit[7] = qs_gf521_copy_bit(state, &in->bit[264]);
    out->bit[8] = qs_gf521_xor_bits(state, &in->bit[4], &in->bit[509]);
    out->bit[9] = qs_gf521_copy_bit(state, &in->bit[265]);
    out->bit[10] = qs_gf521_xor_bits(state, &in->bit[5], &in->bit[510]);
    out->bit[11] = qs_gf521_copy_bit(state, &in->bit[266]);
    out->bit[12] = qs_gf521_xor_bits(state, &in->bit[6], &in->bit[511]);
    out->bit[13] = qs_gf521_copy_bit(state, &in->bit[267]);
    out->bit[14] = qs_gf521_xor_bits(state, &in->bit[7], &in->bit[512]);
    out->bit[15] = qs_gf521_copy_bit(state, &in->bit[268]);
    out->bit[16] = qs_gf521_xor_bits(state, &in->bit[8], &in->bit[513]);
    out->bit[17] = qs_gf521_copy_bit(state, &in->bit[269]);
    out->bit[18] = qs_gf521_xor_bits(state, &in->bit[9], &in->bit[514]);
    out->bit[19] = qs_gf521_copy_bit(state, &in->bit[270]);
    out->bit[20] = qs_gf521_xor_bits(state, &in->bit[10], &in->bit[515]);
    out->bit[21] = qs_gf521_copy_bit(state, &in->bit[271]);
    out->bit[22] = qs_gf521_xor_bits(state, &in->bit[11], &in->bit[516]);
    out->bit[23] = qs_gf521_copy_bit(state, &in->bit[272]);
    out->bit[24] = qs_gf521_xor_bits(state, &in->bit[12], &in->bit[517]);
    out->bit[25] = qs_gf521_copy_bit(state, &in->bit[273]);
    out->bit[26] = qs_gf521_xor_bits(state, &in->bit[13], &in->bit[518]);
    out->bit[27] = qs_gf521_copy_bit(state, &in->bit[274]);
    out->bit[28] = qs_gf521_xor_bits(state, &in->bit[14], &in->bit[519]);
    out->bit[29] = qs_gf521_copy_bit(state, &in->bit[275]);
    out->bit[30] = qs_gf521_xor_bits(state, &in->bit[15], &in->bit[520]);
    out->bit[31] = qs_gf521_copy_bit(state, &in->bit[276]);
    out->bit[32] = qs_gf521_xor_bits(state, &in->bit[16], &in->bit[505]);
    out->bit[33] = qs_gf521_xor_bits(state, &in->bit[261], &in->bit[277]);
    out->bit[34] = qs_gf521_xor_bits(state, &in->bit[17], &in->bit[506]);
    out->bit[35] = qs_gf521_xor_bits(state, &in->bit[262], &in->bit[278]);
    out->bit[36] = qs_gf521_xor_bits(state, &in->bit[18], &in->bit[507]);
    out->bit[37] = qs_gf521_xor_bits(state, &in->bit[263], &in->bit[279]);
    out->bit[38] = qs_gf521_xor_bits(state, &in->bit[19], &in->bit[508]);
    out->bit[39] = qs_gf521_xor_bits(state, &in->bit[264], &in->bit[280]);
    out->bit[40] = qs_gf521_xor_bits(state, &in->bit[20], &in->bit[509]);
    out->bit[41] = qs_gf521_xor_bits(state, &in->bit[265], &in->bit[281]);
    out->bit[42] = qs_gf521_xor_bits(state, &in->bit[21], &in->bit[510]);
    out->bit[43] = qs_gf521_xor_bits(state, &in->bit[266], &in->bit[282]);
    out->bit[44] = qs_gf521_xor_bits(state, &in->bit[22], &in->bit[511]);
    out->bit[45] = qs_gf521_xor_bits(state, &in->bit[267], &in->bit[283]);
    out->bit[46] = qs_gf521_xor_bits(state, &in->bit[23], &in->bit[512]);
    out->bit[47] = qs_gf521_xor_bits(state, &in->bit[268], &in->bit[284]);
    out->bit[48] = qs_gf521_xor_bits(state, &in->bit[24], &in->bit[513]);
    out->bit[49] = qs_gf521_xor_bits(state, &in->bit[269], &in->bit[285]);
    out->bit[50] = qs_gf521_xor_bits(state, &in->bit[25], &in->bit[514]);
    out->bit[51] = qs_gf521_xor_bits(state, &in->bit[270], &in->bit[286]);
    out->bit[52] = qs_gf521_xor_bits(state, &in->bit[26], &in->bit[515]);
    out->bit[53] = qs_gf521_xor_bits(state, &in->bit[271], &in->bit[287]);
    out->bit[54] = qs_gf521_xor_bits(state, &in->bit[27], &in->bit[516]);
    out->bit[55] = qs_gf521_xor_bits(state, &in->bit[272], &in->bit[288]);
    out->bit[56] = qs_gf521_xor_bits(state, &in->bit[28], &in->bit[517]);
    out->bit[57] = qs_gf521_xor_bits(state, &in->bit[273], &in->bit[289]);
    out->bit[58] = qs_gf521_xor_bits(state, &in->bit[29], &in->bit[518]);
    out->bit[59] = qs_gf521_xor_bits(state, &in->bit[274], &in->bit[290]);
    out->bit[60] = qs_gf521_xor_bits(state, &in->bit[30], &in->bit[519]);
    out->bit[61] = qs_gf521_xor_bits(state, &in->bit[275], &in->bit[291]);
    out->bit[62] = qs_gf521_xor_bits(state, &in->bit[31], &in->bit[520]);
    out->bit[63] = qs_gf521_xor_bits(state, &in->bit[276], &in->bit[292]);
    out->bit[64] = qs_gf521_copy_bit(state, &in->bit[32]);
    out->bit[65] = qs_gf521_xor_bits(state, &in->bit[277], &in->bit[293]);
    out->bit[66] = qs_gf521_copy_bit(state, &in->bit[33]);
    out->bit[67] = qs_gf521_xor_bits(state, &in->bit[278], &in->bit[294]);
    out->bit[68] = qs_gf521_copy_bit(state, &in->bit[34]);
    out->bit[69] = qs_gf521_xor_bits(state, &in->bit[279], &in->bit[295]);
    out->bit[70] = qs_gf521_copy_bit(state, &in->bit[35]);
    out->bit[71] = qs_gf521_xor_bits(state, &in->bit[280], &in->bit[296]);
    out->bit[72] = qs_gf521_copy_bit(state, &in->bit[36]);
    out->bit[73] = qs_gf521_xor_bits(state, &in->bit[281], &in->bit[297]);
    out->bit[74] = qs_gf521_copy_bit(state, &in->bit[37]);
    out->bit[75] = qs_gf521_xor_bits(state, &in->bit[282], &in->bit[298]);
    out->bit[76] = qs_gf521_copy_bit(state, &in->bit[38]);
    out->bit[77] = qs_gf521_xor_bits(state, &in->bit[283], &in->bit[299]);
    out->bit[78] = qs_gf521_copy_bit(state, &in->bit[39]);
    out->bit[79] = qs_gf521_xor_bits(state, &in->bit[284], &in->bit[300]);
    out->bit[80] = qs_gf521_copy_bit(state, &in->bit[40]);
    out->bit[81] = qs_gf521_xor_bits(state, &in->bit[285], &in->bit[301]);
    out->bit[82] = qs_gf521_copy_bit(state, &in->bit[41]);
    out->bit[83] = qs_gf521_xor_bits(state, &in->bit[286], &in->bit[302]);
    out->bit[84] = qs_gf521_copy_bit(state, &in->bit[42]);
    out->bit[85] = qs_gf521_xor_bits(state, &in->bit[287], &in->bit[303]);
    out->bit[86] = qs_gf521_copy_bit(state, &in->bit[43]);
    out->bit[87] = qs_gf521_xor_bits(state, &in->bit[288], &in->bit[304]);
    out->bit[88] = qs_gf521_copy_bit(state, &in->bit[44]);
    out->bit[89] = qs_gf521_xor_bits(state, &in->bit[289], &in->bit[305]);
    out->bit[90] = qs_gf521_copy_bit(state, &in->bit[45]);
    out->bit[91] = qs_gf521_xor_bits(state, &in->bit[290], &in->bit[306]);
    out->bit[92] = qs_gf521_copy_bit(state, &in->bit[46]);
    out->bit[93] = qs_gf521_xor_bits(state, &in->bit[291], &in->bit[307]);
    out->bit[94] = qs_gf521_copy_bit(state, &in->bit[47]);
    out->bit[95] = qs_gf521_xor_bits(state, &in->bit[292], &in->bit[308]);
    out->bit[96] = qs_gf521_copy_bit(state, &in->bit[48]);
    out->bit[97] = qs_gf521_xor_bits(state, &in->bit[293], &in->bit[309]);
    out->bit[98] = qs_gf521_copy_bit(state, &in->bit[49]);
    out->bit[99] = qs_gf521_xor_bits(state, &in->bit[294], &in->bit[310]);
    out->bit[100] = qs_gf521_copy_bit(state, &in->bit[50]);
    out->bit[101] = qs_gf521_xor_bits(state, &in->bit[295], &in->bit[311]);
    out->bit[102] = qs_gf521_copy_bit(state, &in->bit[51]);
    out->bit[103] = qs_gf521_xor_bits(state, &in->bit[296], &in->bit[312]);
    out->bit[104] = qs_gf521_copy_bit(state, &in->bit[52]);
    out->bit[105] = qs_gf521_xor_bits(state, &in->bit[297], &in->bit[313]);
    out->bit[106] = qs_gf521_copy_bit(state, &in->bit[53]);
    out->bit[107] = qs_gf521_xor_bits(state, &in->bit[298], &in->bit[314]);
    out->bit[108] = qs_gf521_copy_bit(state, &in->bit[54]);
    out->bit[109] = qs_gf521_xor_bits(state, &in->bit[299], &in->bit[315]);
    out->bit[110] = qs_gf521_copy_bit(state, &in->bit[55]);
    out->bit[111] = qs_gf521_xor_bits(state, &in->bit[300], &in->bit[316]);
    out->bit[112] = qs_gf521_copy_bit(state, &in->bit[56]);
    out->bit[113] = qs_gf521_xor_bits(state, &in->bit[301], &in->bit[317]);
    out->bit[114] = qs_gf521_copy_bit(state, &in->bit[57]);
    out->bit[115] = qs_gf521_xor_bits(state, &in->bit[302], &in->bit[318]);
    out->bit[116] = qs_gf521_copy_bit(state, &in->bit[58]);
    out->bit[117] = qs_gf521_xor_bits(state, &in->bit[303], &in->bit[319]);
    out->bit[118] = qs_gf521_copy_bit(state, &in->bit[59]);
    out->bit[119] = qs_gf521_xor_bits(state, &in->bit[304], &in->bit[320]);
    out->bit[120] = qs_gf521_copy_bit(state, &in->bit[60]);
    out->bit[121] = qs_gf521_xor_bits(state, &in->bit[305], &in->bit[321]);
    out->bit[122] = qs_gf521_copy_bit(state, &in->bit[61]);
    out->bit[123] = qs_gf521_xor_bits(state, &in->bit[306], &in->bit[322]);
    out->bit[124] = qs_gf521_copy_bit(state, &in->bit[62]);
    out->bit[125] = qs_gf521_xor_bits(state, &in->bit[307], &in->bit[323]);
    out->bit[126] = qs_gf521_copy_bit(state, &in->bit[63]);
    out->bit[127] = qs_gf521_xor_bits(state, &in->bit[308], &in->bit[324]);
    out->bit[128] = qs_gf521_copy_bit(state, &in->bit[64]);
    out->bit[129] = qs_gf521_xor_bits(state, &in->bit[309], &in->bit[325]);
    out->bit[130] = qs_gf521_copy_bit(state, &in->bit[65]);
    out->bit[131] = qs_gf521_xor_bits(state, &in->bit[310], &in->bit[326]);
    out->bit[132] = qs_gf521_copy_bit(state, &in->bit[66]);
    out->bit[133] = qs_gf521_xor_bits(state, &in->bit[311], &in->bit[327]);
    out->bit[134] = qs_gf521_copy_bit(state, &in->bit[67]);
    out->bit[135] = qs_gf521_xor_bits(state, &in->bit[312], &in->bit[328]);
    out->bit[136] = qs_gf521_copy_bit(state, &in->bit[68]);
    out->bit[137] = qs_gf521_xor_bits(state, &in->bit[313], &in->bit[329]);
    out->bit[138] = qs_gf521_copy_bit(state, &in->bit[69]);
    out->bit[139] = qs_gf521_xor_bits(state, &in->bit[314], &in->bit[330]);
    out->bit[140] = qs_gf521_copy_bit(state, &in->bit[70]);
    out->bit[141] = qs_gf521_xor_bits(state, &in->bit[315], &in->bit[331]);
    out->bit[142] = qs_gf521_copy_bit(state, &in->bit[71]);
    out->bit[143] = qs_gf521_xor_bits(state, &in->bit[316], &in->bit[332]);
    out->bit[144] = qs_gf521_copy_bit(state, &in->bit[72]);
    out->bit[145] = qs_gf521_xor_bits(state, &in->bit[317], &in->bit[333]);
    out->bit[146] = qs_gf521_copy_bit(state, &in->bit[73]);
    out->bit[147] = qs_gf521_xor_bits(state, &in->bit[318], &in->bit[334]);
    out->bit[148] = qs_gf521_copy_bit(state, &in->bit[74]);
    out->bit[149] = qs_gf521_xor_bits(state, &in->bit[319], &in->bit[335]);
    out->bit[150] = qs_gf521_copy_bit(state, &in->bit[75]);
    out->bit[151] = qs_gf521_xor_bits(state, &in->bit[320], &in->bit[336]);
    out->bit[152] = qs_gf521_copy_bit(state, &in->bit[76]);
    out->bit[153] = qs_gf521_xor_bits(state, &in->bit[321], &in->bit[337]);
    out->bit[154] = qs_gf521_copy_bit(state, &in->bit[77]);
    out->bit[155] = qs_gf521_xor_bits(state, &in->bit[322], &in->bit[338]);
    out->bit[156] = qs_gf521_copy_bit(state, &in->bit[78]);
    out->bit[157] = qs_gf521_xor_bits(state, &in->bit[323], &in->bit[339]);
    out->bit[158] = qs_gf521_copy_bit(state, &in->bit[79]);
    out->bit[159] = qs_gf521_xor_bits(state, &in->bit[324], &in->bit[340]);
    out->bit[160] = qs_gf521_copy_bit(state, &in->bit[80]);
    out->bit[161] = qs_gf521_xor_bits(state, &in->bit[325], &in->bit[341]);
    out->bit[162] = qs_gf521_copy_bit(state, &in->bit[81]);
    out->bit[163] = qs_gf521_xor_bits(state, &in->bit[326], &in->bit[342]);
    out->bit[164] = qs_gf521_copy_bit(state, &in->bit[82]);
    out->bit[165] = qs_gf521_xor_bits(state, &in->bit[327], &in->bit[343]);
    out->bit[166] = qs_gf521_copy_bit(state, &in->bit[83]);
    out->bit[167] = qs_gf521_xor_bits(state, &in->bit[328], &in->bit[344]);
    out->bit[168] = qs_gf521_copy_bit(state, &in->bit[84]);
    out->bit[169] = qs_gf521_xor_bits(state, &in->bit[329], &in->bit[345]);
    out->bit[170] = qs_gf521_copy_bit(state, &in->bit[85]);
    out->bit[171] = qs_gf521_xor_bits(state, &in->bit[330], &in->bit[346]);
    out->bit[172] = qs_gf521_copy_bit(state, &in->bit[86]);
    out->bit[173] = qs_gf521_xor_bits(state, &in->bit[331], &in->bit[347]);
    out->bit[174] = qs_gf521_copy_bit(state, &in->bit[87]);
    out->bit[175] = qs_gf521_xor_bits(state, &in->bit[332], &in->bit[348]);
    out->bit[176] = qs_gf521_copy_bit(state, &in->bit[88]);
    out->bit[177] = qs_gf521_xor_bits(state, &in->bit[333], &in->bit[349]);
    out->bit[178] = qs_gf521_copy_bit(state, &in->bit[89]);
    out->bit[179] = qs_gf521_xor_bits(state, &in->bit[334], &in->bit[350]);
    out->bit[180] = qs_gf521_copy_bit(state, &in->bit[90]);
    out->bit[181] = qs_gf521_xor_bits(state, &in->bit[335], &in->bit[351]);
    out->bit[182] = qs_gf521_copy_bit(state, &in->bit[91]);
    out->bit[183] = qs_gf521_xor_bits(state, &in->bit[336], &in->bit[352]);
    out->bit[184] = qs_gf521_copy_bit(state, &in->bit[92]);
    out->bit[185] = qs_gf521_xor_bits(state, &in->bit[337], &in->bit[353]);
    out->bit[186] = qs_gf521_copy_bit(state, &in->bit[93]);
    out->bit[187] = qs_gf521_xor_bits(state, &in->bit[338], &in->bit[354]);
    out->bit[188] = qs_gf521_copy_bit(state, &in->bit[94]);
    out->bit[189] = qs_gf521_xor_bits(state, &in->bit[339], &in->bit[355]);
    out->bit[190] = qs_gf521_copy_bit(state, &in->bit[95]);
    out->bit[191] = qs_gf521_xor_bits(state, &in->bit[340], &in->bit[356]);
    out->bit[192] = qs_gf521_copy_bit(state, &in->bit[96]);
    out->bit[193] = qs_gf521_xor_bits(state, &in->bit[341], &in->bit[357]);
    out->bit[194] = qs_gf521_copy_bit(state, &in->bit[97]);
    out->bit[195] = qs_gf521_xor_bits(state, &in->bit[342], &in->bit[358]);
    out->bit[196] = qs_gf521_copy_bit(state, &in->bit[98]);
    out->bit[197] = qs_gf521_xor_bits(state, &in->bit[343], &in->bit[359]);
    out->bit[198] = qs_gf521_copy_bit(state, &in->bit[99]);
    out->bit[199] = qs_gf521_xor_bits(state, &in->bit[344], &in->bit[360]);
    out->bit[200] = qs_gf521_copy_bit(state, &in->bit[100]);
    out->bit[201] = qs_gf521_xor_bits(state, &in->bit[345], &in->bit[361]);
    out->bit[202] = qs_gf521_copy_bit(state, &in->bit[101]);
    out->bit[203] = qs_gf521_xor_bits(state, &in->bit[346], &in->bit[362]);
    out->bit[204] = qs_gf521_copy_bit(state, &in->bit[102]);
    out->bit[205] = qs_gf521_xor_bits(state, &in->bit[347], &in->bit[363]);
    out->bit[206] = qs_gf521_copy_bit(state, &in->bit[103]);
    out->bit[207] = qs_gf521_xor_bits(state, &in->bit[348], &in->bit[364]);
    out->bit[208] = qs_gf521_copy_bit(state, &in->bit[104]);
    out->bit[209] = qs_gf521_xor_bits(state, &in->bit[349], &in->bit[365]);
    out->bit[210] = qs_gf521_copy_bit(state, &in->bit[105]);
    out->bit[211] = qs_gf521_xor_bits(state, &in->bit[350], &in->bit[366]);
    out->bit[212] = qs_gf521_copy_bit(state, &in->bit[106]);
    out->bit[213] = qs_gf521_xor_bits(state, &in->bit[351], &in->bit[367]);
    out->bit[214] = qs_gf521_copy_bit(state, &in->bit[107]);
    out->bit[215] = qs_gf521_xor_bits(state, &in->bit[352], &in->bit[368]);
    out->bit[216] = qs_gf521_copy_bit(state, &in->bit[108]);
    out->bit[217] = qs_gf521_xor_bits(state, &in->bit[353], &in->bit[369]);
    out->bit[218] = qs_gf521_copy_bit(state, &in->bit[109]);
    out->bit[219] = qs_gf521_xor_bits(state, &in->bit[354], &in->bit[370]);
    out->bit[220] = qs_gf521_copy_bit(state, &in->bit[110]);
    out->bit[221] = qs_gf521_xor_bits(state, &in->bit[355], &in->bit[371]);
    out->bit[222] = qs_gf521_copy_bit(state, &in->bit[111]);
    out->bit[223] = qs_gf521_xor_bits(state, &in->bit[356], &in->bit[372]);
    out->bit[224] = qs_gf521_copy_bit(state, &in->bit[112]);
    out->bit[225] = qs_gf521_xor_bits(state, &in->bit[357], &in->bit[373]);
    out->bit[226] = qs_gf521_copy_bit(state, &in->bit[113]);
    out->bit[227] = qs_gf521_xor_bits(state, &in->bit[358], &in->bit[374]);
    out->bit[228] = qs_gf521_copy_bit(state, &in->bit[114]);
    out->bit[229] = qs_gf521_xor_bits(state, &in->bit[359], &in->bit[375]);
    out->bit[230] = qs_gf521_copy_bit(state, &in->bit[115]);
    out->bit[231] = qs_gf521_xor_bits(state, &in->bit[360], &in->bit[376]);
    out->bit[232] = qs_gf521_copy_bit(state, &in->bit[116]);
    out->bit[233] = qs_gf521_xor_bits(state, &in->bit[361], &in->bit[377]);
    out->bit[234] = qs_gf521_copy_bit(state, &in->bit[117]);
    out->bit[235] = qs_gf521_xor_bits(state, &in->bit[362], &in->bit[378]);
    out->bit[236] = qs_gf521_copy_bit(state, &in->bit[118]);
    out->bit[237] = qs_gf521_xor_bits(state, &in->bit[363], &in->bit[379]);
    out->bit[238] = qs_gf521_copy_bit(state, &in->bit[119]);
    out->bit[239] = qs_gf521_xor_bits(state, &in->bit[364], &in->bit[380]);
    out->bit[240] = qs_gf521_copy_bit(state, &in->bit[120]);
    out->bit[241] = qs_gf521_xor_bits(state, &in->bit[365], &in->bit[381]);
    out->bit[242] = qs_gf521_copy_bit(state, &in->bit[121]);
    out->bit[243] = qs_gf521_xor_bits(state, &in->bit[366], &in->bit[382]);
    out->bit[244] = qs_gf521_copy_bit(state, &in->bit[122]);
    out->bit[245] = qs_gf521_xor_bits(state, &in->bit[367], &in->bit[383]);
    out->bit[246] = qs_gf521_copy_bit(state, &in->bit[123]);
    out->bit[247] = qs_gf521_xor_bits(state, &in->bit[368], &in->bit[384]);
    out->bit[248] = qs_gf521_copy_bit(state, &in->bit[124]);
    out->bit[249] = qs_gf521_xor_bits(state, &in->bit[369], &in->bit[385]);
    out->bit[250] = qs_gf521_copy_bit(state, &in->bit[125]);
    out->bit[251] = qs_gf521_xor_bits(state, &in->bit[370], &in->bit[386]);
    out->bit[252] = qs_gf521_copy_bit(state, &in->bit[126]);
    out->bit[253] = qs_gf521_xor_bits(state, &in->bit[371], &in->bit[387]);
    out->bit[254] = qs_gf521_copy_bit(state, &in->bit[127]);
    out->bit[255] = qs_gf521_xor_bits(state, &in->bit[372], &in->bit[388]);
    out->bit[256] = qs_gf521_copy_bit(state, &in->bit[128]);
    out->bit[257] = qs_gf521_xor_bits(state, &in->bit[373], &in->bit[389]);
    out->bit[258] = qs_gf521_copy_bit(state, &in->bit[129]);
    out->bit[259] = qs_gf521_xor_bits(state, &in->bit[374], &in->bit[390]);
    out->bit[260] = qs_gf521_copy_bit(state, &in->bit[130]);
    out->bit[261] = qs_gf521_xor_bits(state, &in->bit[375], &in->bit[391]);
    out->bit[262] = qs_gf521_copy_bit(state, &in->bit[131]);
    out->bit[263] = qs_gf521_xor_bits(state, &in->bit[376], &in->bit[392]);
    out->bit[264] = qs_gf521_copy_bit(state, &in->bit[132]);
    out->bit[265] = qs_gf521_xor_bits(state, &in->bit[377], &in->bit[393]);
    out->bit[266] = qs_gf521_copy_bit(state, &in->bit[133]);
    out->bit[267] = qs_gf521_xor_bits(state, &in->bit[378], &in->bit[394]);
    out->bit[268] = qs_gf521_copy_bit(state, &in->bit[134]);
    out->bit[269] = qs_gf521_xor_bits(state, &in->bit[379], &in->bit[395]);
    out->bit[270] = qs_gf521_copy_bit(state, &in->bit[135]);
    out->bit[271] = qs_gf521_xor_bits(state, &in->bit[380], &in->bit[396]);
    out->bit[272] = qs_gf521_copy_bit(state, &in->bit[136]);
    out->bit[273] = qs_gf521_xor_bits(state, &in->bit[381], &in->bit[397]);
    out->bit[274] = qs_gf521_copy_bit(state, &in->bit[137]);
    out->bit[275] = qs_gf521_xor_bits(state, &in->bit[382], &in->bit[398]);
    out->bit[276] = qs_gf521_copy_bit(state, &in->bit[138]);
    out->bit[277] = qs_gf521_xor_bits(state, &in->bit[383], &in->bit[399]);
    out->bit[278] = qs_gf521_copy_bit(state, &in->bit[139]);
    out->bit[279] = qs_gf521_xor_bits(state, &in->bit[384], &in->bit[400]);
    out->bit[280] = qs_gf521_copy_bit(state, &in->bit[140]);
    out->bit[281] = qs_gf521_xor_bits(state, &in->bit[385], &in->bit[401]);
    out->bit[282] = qs_gf521_copy_bit(state, &in->bit[141]);
    out->bit[283] = qs_gf521_xor_bits(state, &in->bit[386], &in->bit[402]);
    out->bit[284] = qs_gf521_copy_bit(state, &in->bit[142]);
    out->bit[285] = qs_gf521_xor_bits(state, &in->bit[387], &in->bit[403]);
    out->bit[286] = qs_gf521_copy_bit(state, &in->bit[143]);
    out->bit[287] = qs_gf521_xor_bits(state, &in->bit[388], &in->bit[404]);
    out->bit[288] = qs_gf521_copy_bit(state, &in->bit[144]);
    out->bit[289] = qs_gf521_xor_bits(state, &in->bit[389], &in->bit[405]);
    out->bit[290] = qs_gf521_copy_bit(state, &in->bit[145]);
    out->bit[291] = qs_gf521_xor_bits(state, &in->bit[390], &in->bit[406]);
    out->bit[292] = qs_gf521_copy_bit(state, &in->bit[146]);
    out->bit[293] = qs_gf521_xor_bits(state, &in->bit[391], &in->bit[407]);
    out->bit[294] = qs_gf521_copy_bit(state, &in->bit[147]);
    out->bit[295] = qs_gf521_xor_bits(state, &in->bit[392], &in->bit[408]);
    out->bit[296] = qs_gf521_copy_bit(state, &in->bit[148]);
    out->bit[297] = qs_gf521_xor_bits(state, &in->bit[393], &in->bit[409]);
    out->bit[298] = qs_gf521_copy_bit(state, &in->bit[149]);
    out->bit[299] = qs_gf521_xor_bits(state, &in->bit[394], &in->bit[410]);
    out->bit[300] = qs_gf521_copy_bit(state, &in->bit[150]);
    out->bit[301] = qs_gf521_xor_bits(state, &in->bit[395], &in->bit[411]);
    out->bit[302] = qs_gf521_copy_bit(state, &in->bit[151]);
    out->bit[303] = qs_gf521_xor_bits(state, &in->bit[396], &in->bit[412]);
    out->bit[304] = qs_gf521_copy_bit(state, &in->bit[152]);
    out->bit[305] = qs_gf521_xor_bits(state, &in->bit[397], &in->bit[413]);
    out->bit[306] = qs_gf521_copy_bit(state, &in->bit[153]);
    out->bit[307] = qs_gf521_xor_bits(state, &in->bit[398], &in->bit[414]);
    out->bit[308] = qs_gf521_copy_bit(state, &in->bit[154]);
    out->bit[309] = qs_gf521_xor_bits(state, &in->bit[399], &in->bit[415]);
    out->bit[310] = qs_gf521_copy_bit(state, &in->bit[155]);
    out->bit[311] = qs_gf521_xor_bits(state, &in->bit[400], &in->bit[416]);
    out->bit[312] = qs_gf521_copy_bit(state, &in->bit[156]);
    out->bit[313] = qs_gf521_xor_bits(state, &in->bit[401], &in->bit[417]);
    out->bit[314] = qs_gf521_copy_bit(state, &in->bit[157]);
    out->bit[315] = qs_gf521_xor_bits(state, &in->bit[402], &in->bit[418]);
    out->bit[316] = qs_gf521_copy_bit(state, &in->bit[158]);
    out->bit[317] = qs_gf521_xor_bits(state, &in->bit[403], &in->bit[419]);
    out->bit[318] = qs_gf521_copy_bit(state, &in->bit[159]);
    out->bit[319] = qs_gf521_xor_bits(state, &in->bit[404], &in->bit[420]);
    out->bit[320] = qs_gf521_copy_bit(state, &in->bit[160]);
    out->bit[321] = qs_gf521_xor_bits(state, &in->bit[405], &in->bit[421]);
    out->bit[322] = qs_gf521_copy_bit(state, &in->bit[161]);
    out->bit[323] = qs_gf521_xor_bits(state, &in->bit[406], &in->bit[422]);
    out->bit[324] = qs_gf521_copy_bit(state, &in->bit[162]);
    out->bit[325] = qs_gf521_xor_bits(state, &in->bit[407], &in->bit[423]);
    out->bit[326] = qs_gf521_copy_bit(state, &in->bit[163]);
    out->bit[327] = qs_gf521_xor_bits(state, &in->bit[408], &in->bit[424]);
    out->bit[328] = qs_gf521_copy_bit(state, &in->bit[164]);
    out->bit[329] = qs_gf521_xor_bits(state, &in->bit[409], &in->bit[425]);
    out->bit[330] = qs_gf521_copy_bit(state, &in->bit[165]);
    out->bit[331] = qs_gf521_xor_bits(state, &in->bit[410], &in->bit[426]);
    out->bit[332] = qs_gf521_copy_bit(state, &in->bit[166]);
    out->bit[333] = qs_gf521_xor_bits(state, &in->bit[411], &in->bit[427]);
    out->bit[334] = qs_gf521_copy_bit(state, &in->bit[167]);
    out->bit[335] = qs_gf521_xor_bits(state, &in->bit[412], &in->bit[428]);
    out->bit[336] = qs_gf521_copy_bit(state, &in->bit[168]);
    out->bit[337] = qs_gf521_xor_bits(state, &in->bit[413], &in->bit[429]);
    out->bit[338] = qs_gf521_copy_bit(state, &in->bit[169]);
    out->bit[339] = qs_gf521_xor_bits(state, &in->bit[414], &in->bit[430]);
    out->bit[340] = qs_gf521_copy_bit(state, &in->bit[170]);
    out->bit[341] = qs_gf521_xor_bits(state, &in->bit[415], &in->bit[431]);
    out->bit[342] = qs_gf521_copy_bit(state, &in->bit[171]);
    out->bit[343] = qs_gf521_xor_bits(state, &in->bit[416], &in->bit[432]);
    out->bit[344] = qs_gf521_copy_bit(state, &in->bit[172]);
    out->bit[345] = qs_gf521_xor_bits(state, &in->bit[417], &in->bit[433]);
    out->bit[346] = qs_gf521_copy_bit(state, &in->bit[173]);
    out->bit[347] = qs_gf521_xor_bits(state, &in->bit[418], &in->bit[434]);
    out->bit[348] = qs_gf521_copy_bit(state, &in->bit[174]);
    out->bit[349] = qs_gf521_xor_bits(state, &in->bit[419], &in->bit[435]);
    out->bit[350] = qs_gf521_copy_bit(state, &in->bit[175]);
    out->bit[351] = qs_gf521_xor_bits(state, &in->bit[420], &in->bit[436]);
    out->bit[352] = qs_gf521_copy_bit(state, &in->bit[176]);
    out->bit[353] = qs_gf521_xor_bits(state, &in->bit[421], &in->bit[437]);
    out->bit[354] = qs_gf521_copy_bit(state, &in->bit[177]);
    out->bit[355] = qs_gf521_xor_bits(state, &in->bit[422], &in->bit[438]);
    out->bit[356] = qs_gf521_copy_bit(state, &in->bit[178]);
    out->bit[357] = qs_gf521_xor_bits(state, &in->bit[423], &in->bit[439]);
    out->bit[358] = qs_gf521_copy_bit(state, &in->bit[179]);
    out->bit[359] = qs_gf521_xor_bits(state, &in->bit[424], &in->bit[440]);
    out->bit[360] = qs_gf521_copy_bit(state, &in->bit[180]);
    out->bit[361] = qs_gf521_xor_bits(state, &in->bit[425], &in->bit[441]);
    out->bit[362] = qs_gf521_copy_bit(state, &in->bit[181]);
    out->bit[363] = qs_gf521_xor_bits(state, &in->bit[426], &in->bit[442]);
    out->bit[364] = qs_gf521_copy_bit(state, &in->bit[182]);
    out->bit[365] = qs_gf521_xor_bits(state, &in->bit[427], &in->bit[443]);
    out->bit[366] = qs_gf521_copy_bit(state, &in->bit[183]);
    out->bit[367] = qs_gf521_xor_bits(state, &in->bit[428], &in->bit[444]);
    out->bit[368] = qs_gf521_copy_bit(state, &in->bit[184]);
    out->bit[369] = qs_gf521_xor_bits(state, &in->bit[429], &in->bit[445]);
    out->bit[370] = qs_gf521_copy_bit(state, &in->bit[185]);
    out->bit[371] = qs_gf521_xor_bits(state, &in->bit[430], &in->bit[446]);
    out->bit[372] = qs_gf521_copy_bit(state, &in->bit[186]);
    out->bit[373] = qs_gf521_xor_bits(state, &in->bit[431], &in->bit[447]);
    out->bit[374] = qs_gf521_copy_bit(state, &in->bit[187]);
    out->bit[375] = qs_gf521_xor_bits(state, &in->bit[432], &in->bit[448]);
    out->bit[376] = qs_gf521_copy_bit(state, &in->bit[188]);
    out->bit[377] = qs_gf521_xor_bits(state, &in->bit[433], &in->bit[449]);
    out->bit[378] = qs_gf521_copy_bit(state, &in->bit[189]);
    out->bit[379] = qs_gf521_xor_bits(state, &in->bit[434], &in->bit[450]);
    out->bit[380] = qs_gf521_copy_bit(state, &in->bit[190]);
    out->bit[381] = qs_gf521_xor_bits(state, &in->bit[435], &in->bit[451]);
    out->bit[382] = qs_gf521_copy_bit(state, &in->bit[191]);
    out->bit[383] = qs_gf521_xor_bits(state, &in->bit[436], &in->bit[452]);
    out->bit[384] = qs_gf521_copy_bit(state, &in->bit[192]);
    out->bit[385] = qs_gf521_xor_bits(state, &in->bit[437], &in->bit[453]);
    out->bit[386] = qs_gf521_copy_bit(state, &in->bit[193]);
    out->bit[387] = qs_gf521_xor_bits(state, &in->bit[438], &in->bit[454]);
    out->bit[388] = qs_gf521_copy_bit(state, &in->bit[194]);
    out->bit[389] = qs_gf521_xor_bits(state, &in->bit[439], &in->bit[455]);
    out->bit[390] = qs_gf521_copy_bit(state, &in->bit[195]);
    out->bit[391] = qs_gf521_xor_bits(state, &in->bit[440], &in->bit[456]);
    out->bit[392] = qs_gf521_copy_bit(state, &in->bit[196]);
    out->bit[393] = qs_gf521_xor_bits(state, &in->bit[441], &in->bit[457]);
    out->bit[394] = qs_gf521_copy_bit(state, &in->bit[197]);
    out->bit[395] = qs_gf521_xor_bits(state, &in->bit[442], &in->bit[458]);
    out->bit[396] = qs_gf521_copy_bit(state, &in->bit[198]);
    out->bit[397] = qs_gf521_xor_bits(state, &in->bit[443], &in->bit[459]);
    out->bit[398] = qs_gf521_copy_bit(state, &in->bit[199]);
    out->bit[399] = qs_gf521_xor_bits(state, &in->bit[444], &in->bit[460]);
    out->bit[400] = qs_gf521_copy_bit(state, &in->bit[200]);
    out->bit[401] = qs_gf521_xor_bits(state, &in->bit[445], &in->bit[461]);
    out->bit[402] = qs_gf521_copy_bit(state, &in->bit[201]);
    out->bit[403] = qs_gf521_xor_bits(state, &in->bit[446], &in->bit[462]);
    out->bit[404] = qs_gf521_copy_bit(state, &in->bit[202]);
    out->bit[405] = qs_gf521_xor_bits(state, &in->bit[447], &in->bit[463]);
    out->bit[406] = qs_gf521_copy_bit(state, &in->bit[203]);
    out->bit[407] = qs_gf521_xor_bits(state, &in->bit[448], &in->bit[464]);
    out->bit[408] = qs_gf521_copy_bit(state, &in->bit[204]);
    out->bit[409] = qs_gf521_xor_bits(state, &in->bit[449], &in->bit[465]);
    out->bit[410] = qs_gf521_copy_bit(state, &in->bit[205]);
    out->bit[411] = qs_gf521_xor_bits(state, &in->bit[450], &in->bit[466]);
    out->bit[412] = qs_gf521_copy_bit(state, &in->bit[206]);
    out->bit[413] = qs_gf521_xor_bits(state, &in->bit[451], &in->bit[467]);
    out->bit[414] = qs_gf521_copy_bit(state, &in->bit[207]);
    out->bit[415] = qs_gf521_xor_bits(state, &in->bit[452], &in->bit[468]);
    out->bit[416] = qs_gf521_copy_bit(state, &in->bit[208]);
    out->bit[417] = qs_gf521_xor_bits(state, &in->bit[453], &in->bit[469]);
    out->bit[418] = qs_gf521_copy_bit(state, &in->bit[209]);
    out->bit[419] = qs_gf521_xor_bits(state, &in->bit[454], &in->bit[470]);
    out->bit[420] = qs_gf521_copy_bit(state, &in->bit[210]);
    out->bit[421] = qs_gf521_xor_bits(state, &in->bit[455], &in->bit[471]);
    out->bit[422] = qs_gf521_copy_bit(state, &in->bit[211]);
    out->bit[423] = qs_gf521_xor_bits(state, &in->bit[456], &in->bit[472]);
    out->bit[424] = qs_gf521_copy_bit(state, &in->bit[212]);
    out->bit[425] = qs_gf521_xor_bits(state, &in->bit[457], &in->bit[473]);
    out->bit[426] = qs_gf521_copy_bit(state, &in->bit[213]);
    out->bit[427] = qs_gf521_xor_bits(state, &in->bit[458], &in->bit[474]);
    out->bit[428] = qs_gf521_copy_bit(state, &in->bit[214]);
    out->bit[429] = qs_gf521_xor_bits(state, &in->bit[459], &in->bit[475]);
    out->bit[430] = qs_gf521_copy_bit(state, &in->bit[215]);
    out->bit[431] = qs_gf521_xor_bits(state, &in->bit[460], &in->bit[476]);
    out->bit[432] = qs_gf521_copy_bit(state, &in->bit[216]);
    out->bit[433] = qs_gf521_xor_bits(state, &in->bit[461], &in->bit[477]);
    out->bit[434] = qs_gf521_copy_bit(state, &in->bit[217]);
    out->bit[435] = qs_gf521_xor_bits(state, &in->bit[462], &in->bit[478]);
    out->bit[436] = qs_gf521_copy_bit(state, &in->bit[218]);
    out->bit[437] = qs_gf521_xor_bits(state, &in->bit[463], &in->bit[479]);
    out->bit[438] = qs_gf521_copy_bit(state, &in->bit[219]);
    out->bit[439] = qs_gf521_xor_bits(state, &in->bit[464], &in->bit[480]);
    out->bit[440] = qs_gf521_copy_bit(state, &in->bit[220]);
    out->bit[441] = qs_gf521_xor_bits(state, &in->bit[465], &in->bit[481]);
    out->bit[442] = qs_gf521_copy_bit(state, &in->bit[221]);
    out->bit[443] = qs_gf521_xor_bits(state, &in->bit[466], &in->bit[482]);
    out->bit[444] = qs_gf521_copy_bit(state, &in->bit[222]);
    out->bit[445] = qs_gf521_xor_bits(state, &in->bit[467], &in->bit[483]);
    out->bit[446] = qs_gf521_copy_bit(state, &in->bit[223]);
    out->bit[447] = qs_gf521_xor_bits(state, &in->bit[468], &in->bit[484]);
    out->bit[448] = qs_gf521_copy_bit(state, &in->bit[224]);
    out->bit[449] = qs_gf521_xor_bits(state, &in->bit[469], &in->bit[485]);
    out->bit[450] = qs_gf521_copy_bit(state, &in->bit[225]);
    out->bit[451] = qs_gf521_xor_bits(state, &in->bit[470], &in->bit[486]);
    out->bit[452] = qs_gf521_copy_bit(state, &in->bit[226]);
    out->bit[453] = qs_gf521_xor_bits(state, &in->bit[471], &in->bit[487]);
    out->bit[454] = qs_gf521_copy_bit(state, &in->bit[227]);
    out->bit[455] = qs_gf521_xor_bits(state, &in->bit[472], &in->bit[488]);
    out->bit[456] = qs_gf521_copy_bit(state, &in->bit[228]);
    out->bit[457] = qs_gf521_xor_bits(state, &in->bit[473], &in->bit[489]);
    out->bit[458] = qs_gf521_copy_bit(state, &in->bit[229]);
    out->bit[459] = qs_gf521_xor_bits(state, &in->bit[474], &in->bit[490]);
    out->bit[460] = qs_gf521_copy_bit(state, &in->bit[230]);
    out->bit[461] = qs_gf521_xor_bits(state, &in->bit[475], &in->bit[491]);
    out->bit[462] = qs_gf521_copy_bit(state, &in->bit[231]);
    out->bit[463] = qs_gf521_xor_bits(state, &in->bit[476], &in->bit[492]);
    out->bit[464] = qs_gf521_copy_bit(state, &in->bit[232]);
    out->bit[465] = qs_gf521_xor_bits(state, &in->bit[477], &in->bit[493]);
    out->bit[466] = qs_gf521_copy_bit(state, &in->bit[233]);
    out->bit[467] = qs_gf521_xor_bits(state, &in->bit[478], &in->bit[494]);
    out->bit[468] = qs_gf521_copy_bit(state, &in->bit[234]);
    out->bit[469] = qs_gf521_xor_bits(state, &in->bit[479], &in->bit[495]);
    out->bit[470] = qs_gf521_copy_bit(state, &in->bit[235]);
    out->bit[471] = qs_gf521_xor_bits(state, &in->bit[480], &in->bit[496]);
    out->bit[472] = qs_gf521_copy_bit(state, &in->bit[236]);
    out->bit[473] = qs_gf521_xor_bits(state, &in->bit[481], &in->bit[497]);
    out->bit[474] = qs_gf521_copy_bit(state, &in->bit[237]);
    out->bit[475] = qs_gf521_xor_bits(state, &in->bit[482], &in->bit[498]);
    out->bit[476] = qs_gf521_copy_bit(state, &in->bit[238]);
    out->bit[477] = qs_gf521_xor_bits(state, &in->bit[483], &in->bit[499]);
    out->bit[478] = qs_gf521_copy_bit(state, &in->bit[239]);
    out->bit[479] = qs_gf521_xor_bits(state, &in->bit[484], &in->bit[500]);
    out->bit[480] = qs_gf521_copy_bit(state, &in->bit[240]);
    out->bit[481] = qs_gf521_xor_bits(state, &in->bit[485], &in->bit[501]);
    out->bit[482] = qs_gf521_copy_bit(state, &in->bit[241]);
    out->bit[483] = qs_gf521_xor_bits(state, &in->bit[486], &in->bit[502]);
    out->bit[484] = qs_gf521_copy_bit(state, &in->bit[242]);
    out->bit[485] = qs_gf521_xor_bits(state, &in->bit[487], &in->bit[503]);
    out->bit[486] = qs_gf521_copy_bit(state, &in->bit[243]);
    out->bit[487] = qs_gf521_xor_bits(state, &in->bit[488], &in->bit[504]);
    out->bit[488] = qs_gf521_copy_bit(state, &in->bit[244]);
    out->bit[489] = qs_gf521_xor_bits(state, &in->bit[489], &in->bit[505]);
    out->bit[490] = qs_gf521_copy_bit(state, &in->bit[245]);
    out->bit[491] = qs_gf521_xor_bits(state, &in->bit[490], &in->bit[506]);
    out->bit[492] = qs_gf521_copy_bit(state, &in->bit[246]);
    out->bit[493] = qs_gf521_xor_bits(state, &in->bit[491], &in->bit[507]);
    out->bit[494] = qs_gf521_copy_bit(state, &in->bit[247]);
    out->bit[495] = qs_gf521_xor_bits(state, &in->bit[492], &in->bit[508]);
    out->bit[496] = qs_gf521_copy_bit(state, &in->bit[248]);
    out->bit[497] = qs_gf521_xor_bits(state, &in->bit[493], &in->bit[509]);
    out->bit[498] = qs_gf521_copy_bit(state, &in->bit[249]);
    out->bit[499] = qs_gf521_xor_bits(state, &in->bit[494], &in->bit[510]);
    out->bit[500] = qs_gf521_copy_bit(state, &in->bit[250]);
    out->bit[501] = qs_gf521_xor_bits(state, &in->bit[495], &in->bit[511]);
    out->bit[502] = qs_gf521_copy_bit(state, &in->bit[251]);
    out->bit[503] = qs_gf521_xor_bits(state, &in->bit[496], &in->bit[512]);
    out->bit[504] = qs_gf521_copy_bit(state, &in->bit[252]);
    out->bit[505] = qs_gf521_xor_bits(state, &in->bit[497], &in->bit[513]);
    out->bit[506] = qs_gf521_copy_bit(state, &in->bit[253]);
    out->bit[507] = qs_gf521_xor_bits(state, &in->bit[498], &in->bit[514]);
    out->bit[508] = qs_gf521_copy_bit(state, &in->bit[254]);
    out->bit[509] = qs_gf521_xor_bits(state, &in->bit[499], &in->bit[515]);
    out->bit[510] = qs_gf521_copy_bit(state, &in->bit[255]);
    out->bit[511] = qs_gf521_xor_bits(state, &in->bit[500], &in->bit[516]);
    out->bit[512] = qs_gf521_copy_bit(state, &in->bit[256]);
    out->bit[513] = qs_gf521_xor_bits(state, &in->bit[501], &in->bit[517]);
    out->bit[514] = qs_gf521_copy_bit(state, &in->bit[257]);
    out->bit[515] = qs_gf521_xor_bits(state, &in->bit[502], &in->bit[518]);
    out->bit[516] = qs_gf521_copy_bit(state, &in->bit[258]);
    out->bit[517] = qs_gf521_xor_bits(state, &in->bit[503], &in->bit[519]);
    out->bit[518] = qs_gf521_copy_bit(state, &in->bit[259]);
    out->bit[519] = qs_gf521_xor_bits(state, &in->bit[504], &in->bit[520]);
    out->bit[520] = qs_gf521_copy_bit(state, &in->bit[260]);
}

void qs_gf521_square(
    const quicksilver_state* state, qs_gf521_bits* out, const qs_gf521_bits* in)
{
    if (out == in) {
        qs_gf521_bits tmp;
        qs_gf521_square_noalias(state, &tmp, in);
        *out = tmp;
    } else {
        qs_gf521_square_noalias(state, out, in);
    }
}

void qs_gf521_frobenius(
    const quicksilver_state* state, qs_gf521_bits* out,
    const qs_gf521_bits* in, unsigned exponent)
{
    if (exponent == 0) {
        for (size_t i = 0; i < BLOCK521_BITS; ++i)
            out->bit[i] = qs_gf521_copy_bit(state, &in->bit[i]);
        return;
    }
    if (exponent == 1) {
        qs_gf521_square(state, out, in);
        return;
    }

    qs_gf521_bits scratch[2];
    const qs_gf521_bits* current = in;
    for (unsigned round = 0; round < exponent - 1; ++round) {
        qs_gf521_bits* next = &scratch[round & 1];
        qs_gf521_square_noalias(state, next, current);
        current = next;
    }
    qs_gf521_square_noalias(state, out, current);
}

void qs_gf521_shift_reduce(
    const quicksilver_state* state, qs_gf521_bits* out,
    const qs_gf521_bits* in, size_t shift)
{
    assert(shift < BLOCK521_BITS);
    quicksilver_vec_gf2 tmp[2 * BLOCK521_BITS - 1];

    for (size_t i = 0; i < 2 * BLOCK521_BITS - 1; ++i) {
        tmp[i] = quicksilver_zero_gf2();
    }
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        tmp[bit + shift] = quicksilver_add_gf2(state, tmp[bit + shift], in->bit[bit]);
    }
    for (int pos = 2 * BLOCK521_BITS - 2; pos >= BLOCK521_BITS; --pos) {
        const quicksilver_vec_gf2 term = tmp[pos];
        tmp[pos] = quicksilver_zero_gf2();
        tmp[pos - BLOCK521_BITS + BLOCK521_REDUCTION_TERM] = quicksilver_add_gf2(
            state, tmp[pos - BLOCK521_BITS + BLOCK521_REDUCTION_TERM], term);
        tmp[pos - BLOCK521_BITS] = quicksilver_add_gf2(
            state, tmp[pos - BLOCK521_BITS], term);
    }
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        out->bit[bit] = tmp[bit];
    }
}

GW_STATIC_ASSERT(SECURITY_PARAM == 512 && POLY_VEC_LEN == 1,
               "GF521 hash fusion requires scalar GF512 authentication");
GW_STATIC_ASSERT(BLOCK521_BITS == 521 && BLOCK521_REDUCTION_TERM == 32,
               "GF521 projection recurrence assumes t^521 + t^32 + 1");
GW_STATIC_ASSERT(HASHER_GFSECPAR_KEY_POWS == 2,
               "GF521 block append assumes two-coefficient hash groups");

typedef struct {
    poly_secpar_vec weights[2 * BLOCK521_BITS - 1];
    poly_secpar_vec r, defect, r520, r521, r522;
} qs_gf521_projection_key;

static inline poly_secpar_vec qs_gf521_mac_mul(poly_secpar_vec a, poly_secpar_vec b)
{
    return poly_2secpar_reduce_secpar(poly_secpar_mul(a, b));
}

static void qs_gf521_projection_init(qs_gf521_projection_key* key, poly_secpar_vec r)
{

    key->r = r;
    key->weights[520] = poly_secpar_set_low32(1);
    for (int k = 519; k >= 0; --k)
        key->weights[k] = qs_gf521_mac_mul(r, key->weights[k + 1]);
    for (size_t k = 521; k <= 1040; ++k)
        key->weights[k] = poly_secpar_add(key->weights[k - 521], key->weights[k - 489]);
    key->r520 = key->weights[0];
    key->r521 = qs_gf521_mac_mul(r, key->r520);
    key->r522 = qs_gf521_mac_mul(r, key->r521);
    key->defect = poly_secpar_add(poly_secpar_set_low32(1),
        poly_secpar_add(key->r521, key->weights[31]));
}

static poly_secpar_vec qs_gf521_project_product(
    const qs_gf521_projection_key* key,
    const poly_secpar_vec a[BLOCK521_BITS], const poly_secpar_vec b[BLOCK521_BITS])
{

    poly_2secpar_vec initial = poly_2secpar_from_secpar(b[0]);
    for (size_t j = 1; j < BLOCK521_BITS; ++j)
        initial = poly_2secpar_add(initial, poly_secpar_mul(key->weights[520 + j], b[j]));
    poly_secpar_vec v = poly_2secpar_reduce_secpar(initial);
    poly_2secpar_vec result = poly_secpar_mul(a[520], v);

    for (int i = 519; i >= 0; --i) {
        poly_secpar_vec correction = b[520 - i];
        if (i >= 489)
            correction = poly_secpar_add(correction, b[1009 - i]);
        v = poly_2secpar_reduce_secpar(poly_2secpar_add(
            poly_secpar_mul(key->r, v), poly_secpar_mul(key->defect, correction)));
        result = poly_2secpar_add(result, poly_secpar_mul(a[i], v));
    }
    return poly_2secpar_reduce_secpar(result);
}

static void qs_gf521_hash_append(
    hasher_gfsecpar_state* state, const qs_gf521_projection_key* key,
    poly_secpar_vec contribution)
{

    const poly_secpar_vec previous = poly_2secpar_reduce_secpar(state->state);
    poly_secpar_vec next;
    if (state->pow == 0) {
        next = poly_secpar_add(qs_gf521_mac_mul(key->r520, previous), contribution);
        state->pow = -1;
    } else {
        assert(state->pow == -1 || state->pow == 1);
        const poly_secpar_vec factor = state->pow == -1 ? key->r522 : key->r520;
        next = poly_2secpar_reduce_secpar(poly_2secpar_add(
            poly_secpar_mul(factor, previous), poly_secpar_mul(key->r, contribution)));
        state->pow = 0;
    }
    state->state = poly_2secpar_from_secpar(next);
}

static void qs_gf521_hash64_append(
    hasher_gfsecpar_64_state* state, const qs_gf521_projection_key* key,
    poly_secpar_vec contribution)
{

    state->state = poly_secpar_add(qs_gf521_mac_mul(key->r521, state->state), contribution);
}

void qs_gf521_mul_constraints(
    quicksilver_state* state, const qs_gf521_bits* x,
    const qs_gf521_bits* y, const qs_gf521_bits* z, size_t count)
{
    if (count == 0)
        return;
    qs_gf521_projection_key keys[2];
    qs_gf521_projection_init(&keys[0], state->key_secpar.key_pows[0]);
    qs_gf521_projection_init(&keys[1], poly_secpar_from_64(state->key_64.key));

    for (size_t relation = 0; relation < count; ++relation) {
        poly_secpar_vec a[BLOCK521_BITS], b[BLOCK521_BITS];
        poly_secpar_vec a_plus_value[BLOCK521_BITS], b_plus_value[BLOCK521_BITS];
        for (size_t i = 0; i < BLOCK521_BITS; ++i) {
            a[i] = x[relation].bit[i].mac;
            b[i] = y[relation].bit[i].mac;
            if (!state->verifier) {
                a_plus_value[i] = poly_secpar_add(a[i], poly_secpar_from_1(x[relation].bit[i].value));
                b_plus_value[i] = poly_secpar_add(b[i], poly_secpar_from_1(y[relation].bit[i].value));
            }
        }

        for (size_t h = 0; h < 2; ++h) {
            const qs_gf521_projection_key* key = &keys[h];
            poly_secpar_vec constant = qs_gf521_project_product(key, a, b);
            poly_2secpar_vec z_sum = poly_2secpar_set_zero();
            for (size_t i = 0; i < BLOCK521_BITS; ++i) {
                poly_secpar_vec zi = z[relation].bit[i].mac;
                if (!state->verifier)
                    zi = poly_secpar_add(zi, poly_secpar_from_1(z[relation].bit[i].value));
                z_sum = poly_2secpar_add(z_sum, poly_secpar_mul(key->weights[i], zi));
            }
            const poly_secpar_vec z_projection = poly_2secpar_reduce_secpar(z_sum);
            poly_secpar_vec linear = poly_secpar_set_zero();
            if (state->verifier) {

                constant = poly_secpar_add(constant, qs_gf521_mac_mul(state->delta, z_projection));
            } else {

                linear = poly_secpar_add(constant, poly_secpar_add(z_projection,
                    qs_gf521_project_product(key, a_plus_value, b_plus_value)));
            }
            if (h == 0) {
                qs_gf521_hash_append(&state->state_secpar_const, key, constant);
                if (!state->verifier)
                    qs_gf521_hash_append(&state->state_secpar_linear, key, linear);
            } else {
                qs_gf521_hash64_append(&state->state_64_const, key, constant);
                if (!state->verifier)
                    qs_gf521_hash64_append(&state->state_64_linear, key, linear);
            }
        }
    }
}

void qs_gf521_mul_constraint(
    quicksilver_state* state, const qs_gf521_bits* x,
    const qs_gf521_bits* y, const qs_gf521_bits* z)
{
    qs_gf521_mul_constraints(state, x, y, z, 1);
}

void qs_gf521_dot_constraint(
    quicksilver_state* state, const qs_gf521_bits* y, const block521* alpha)
{
    quicksilver_vec_gf2 dot = quicksilver_zero_gf2();
    for (size_t bit = 0; bit < BLOCK521_BITS; ++bit) {
        if ((alpha->data[bit >> 6] >> (bit & 63)) & 1ULL) {
            dot = quicksilver_add_gf2(state, dot, y->bit[bit]);
        }
    }
    quicksilver_inverse_constraint(
        state, quicksilver_combine_1_bit(state, dot), quicksilver_one_gfsecpar(state));
}
