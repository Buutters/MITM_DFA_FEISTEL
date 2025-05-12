import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PiccoloCipher {
    // S-box
    public static final int[] S_BOX = {
            0xE, 0x4, 0xB, 0x2, 0x3, 0x8, 0x0, 0x9,
            0x1, 0xA, 0x7, 0xF, 0x6, 0xC, 0x5, 0xD
    };
    public static final int[][] MIX_COLUMNS_MATRIX_1 = {
            {0xE, 0xB, 0xD, 0x9},
            {0x9, 0xE, 0xB, 0xD},
            {0xD, 0x9, 0xE, 0xB},
            {0xB, 0xD, 0x9, 0xE}
    };

    public static int[] pLayer_1(int[] input) {
        int[] mixed = new int[4];
        for (int i = 0; i < 4; i++) {
            mixed[i] = 0;
            for (int j = 0; j < 4; j++) {
                mixed[i] ^= gfMultiply(MIX_COLUMNS_MATRIX_1[i][j], input[j]);
            }
        }
        return mixed;
    }

    // Convert 16-bit input to int[4]
    public static int[] toIntArray(int input) {
        return new int[]{
                (input >> 12) & 0xF,
                (input >> 8) & 0xF,
                (input >> 4) & 0xF,
                input & 0xF
        };
    }

    public static int[] to8IntArray(int input) {
        return new int[]{
                (input >> 28) & 0xF,
                (input >> 24) & 0xF,
                (input >> 20) & 0xF,
                (input >> 16) & 0xF,
                (input >> 12) & 0xF,
                (input >> 8) & 0xF,
                (input >> 4) & 0xF,
                input & 0xF
        };
    }

    public static final int[] constValue = {
            0x071c293d, 0x1f1a253e, 0x1718213f, 0x2f163d38, 0x27143939,
            0x3f12353a, 0x3710313b, 0x4f0e0d34, 0x470c0935, 0x5f0a0536,
            0x57080137, 0x6f061d30, 0x67041931, 0x7f021532, 0x77001133,
            0x8f3e6d2c, 0x873c692d, 0x9f3a652e, 0x9738612f, 0xaf367d28,
            0xa7347929, 0xbf32752a, 0xb730712b, 0xcf2e4d24, 0xc72c4925
    };

    public static int[] xorArray(int[] a, int[] b) {
        int[] c= new int[a.length];
        for (int i = 0; i < a.length; i++) {
            c[i] =a[i] ^ b[i];
        }
        return c;
    }

    // Convert int[4] back to 16-bit integer
    public static int fromIntArray(int[] input) {
        return (input[0] << 12) | (input[1] << 8) | (input[2] << 4) | input[3];
    }

    // MixColumn matrix
    private static final int[][] MIX_COLUMNS_MATRIX = {
            {0x2, 0x3, 0x1, 0x1},
            {0x1, 0x2, 0x3, 0x1},
            {0x1, 0x1, 0x2, 0x3},
            {0x3, 0x1, 0x1, 0x2}
    };

    // RP Permutation for half-nibbles
    private static final int[] RP_PERMUTATION = {4,5, 14,15, 8,9, 2,3, 12,13, 6,7, 0,1, 10,11};

    // GF(2^4) multiplication with modulus x^4 + x + 1
    static int gfMultiply(int b, int a) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            int highBit = a & 0x8;
            a <<= 1;
            if (highBit != 0) {
                a ^= 0x13; // Modulus x^4 + x + 1 (0b10011)
            }
            b >>= 1;
        }
        return result & 0xF;
    }

    // S-layer
    private static int[] sLayer(int[] input) {
        int[] output = new int[4];
        for (int i = 0; i < 4; i++) {
            output[i] = S_BOX[input[i]];
        }
        return output;
    }

    // P-layer (MixColumns)
    private static int[] pLayer(int[] input) {
        int[] mixed = new int[4];
        for (int i = 0; i < 4; i++) {
            mixed[i] = 0;
            for (int j = 0; j < 4; j++) {
                mixed[i] ^= gfMultiply(MIX_COLUMNS_MATRIX[i][j], input[j]);
            }
        }
        return mixed;
    }
    static final int[] S_BOX_1 = {
            0x6, 0x8, 0x3, 0x4, 0x1, 0xE, 0xC, 0xA,
            0x5, 0x7, 0x9, 0x2, 0xD, 0xF, 0x0, 0xB
    };
    static int[] sLayer_1(int[] input) {
        int[] output = new int[4];
        for (int i = 0; i < 4; i++) {
            output[i] = S_BOX_1[input[i]];
        }
        return output;
    }
    public static int[] F_1(int[] input) {
        return sLayer_1(pLayer_1(sLayer_1(input)));
    }
    // F function
    static int[] F(int[] input) {
        return sLayer(pLayer(sLayer(input)));
    }

    // Round Key Scheduling (Half-nibble based)
    private static int[][] keySchedule(int[] key) {
        int[][] roundKeys = new int[25][8];
        for (int i = 0; i < 25; i++) {
            int k0 = (i % 5 == 0 || i % 5 == 2) ? key[2] : (i % 5 == 1 || i % 5 == 4) ? key[0] : key[4];
            int k1 = (i % 5 == 0 || i % 5 == 2) ? key[3] : (i % 5 == 1 || i % 5 == 4) ? key[1] : key[4];
            for (int j = 0; j < 8; j++) {
                roundKeys[i][j] = ((j < 4) ? (k0 >> (12 - 4 * j)) : (k1 >> (28 - 4 * j))) & 0xF;
            }
            roundKeys[i] = xorArray(roundKeys[i],  to8IntArray(constValue[i]));
        }
        return roundKeys;
    }

    // Constant XOR value
    private static final int CON_XOR_1 = 0x0F1E;
    private static final int CON_XOR_2 = 0x2D3C;

    // Generate round constants
    private static int[] generateRoundConstants(int round) {
        int c_i = round & 0x1F;
        int c_next = (round + 1) & 0x1F;
        int constant = (c_next << 11)  ^ (c_next << 1) ;
        constant ^= CON_XOR_1;
        int constant_2 = (c_next << 10)  ^ (c_next );
        constant_2 ^= CON_XOR_2;
        int[] result = new int[8];
        for (int j = 0; j < 4; j++) {
            result[j] = (constant >> (12 - 4 * j)) & 0xF;
            result[4+j] = (constant_2 >> (12 - 4 * j)) & 0xF;
        }
        return result;
    }

    private static int[][] whiteKeySchedule(int[] key) {
        int[][] roundKeys = new int[4][4];
        for (int j = 0; j < 2; j++) {
            roundKeys[0][j] = (key[0] >> (12 - 4 * j)) & 0xF;
            roundKeys[1][j] = (key[1] >> (12 - 4 * j)) & 0xF;
            roundKeys[2][j] = (key[4] >> (12 - 4 * j)) & 0xF;
            roundKeys[3][j] = (key[3] >> (12 - 4 * j)) & 0xF;
        }
        for (int j = 2; j < 4; j++) {
            roundKeys[0][j] = (key[1] >> (12 - 4 * j)) & 0xF;
            roundKeys[1][j] = (key[0] >> (12 - 4 * j)) & 0xF;
            roundKeys[2][j] = (key[3] >> (12 - 4 * j)) & 0xF;
            roundKeys[3][j] = (key[4] >> (12 - 4 * j)) & 0xF;
        }
        return roundKeys;
    }

    // RP Permutation for half-nibbles
    private static int[] rpPermutation(int[] state) {
        int[] permuted = new int[16];
        for (int i = 0; i < 16; i++) {
            permuted[i] = state[RP_PERMUTATION[i]];
        }
        return permuted;
    }

    // Piccolo Encryption
    public static int[] encrypt(int[] state1, int[] key) {
        int[] state = state1.clone();
        int[][] roundKeys = keySchedule(key);
        int[][] whiteKeys = whiteKeySchedule(key);
        for (int j = 0; j < 4; j++) {
            state[j] ^=  whiteKeys[0][j];
            state[8 + j] ^=  whiteKeys[1][j];
        }
        for (int i = 0; i < 25; i++) {
            if(i == 22){
//                System.out.println();
//                System.out.println();
            }

            int[] fA = F(new int[]{state[0], state[1], state[2], state[3]});
            int[] fC = F(new int[]{state[8], state[9], state[10], state[11]});

//            if(i == 21) {
//                System.out.println(fA[3]);
//            }

            for (int j = 0; j < 4; j++) {
                state[4 + j] ^= fA[j] ^ roundKeys[i][j];
                state[12 + j] ^= fC[j] ^ roundKeys[i][4 + j];
            }

            if(i!= 24) state = rpPermutation(state);
        }
        for (int j = 0; j < 4; j++) {
            state[j] ^=  whiteKeys[2][j];
            state[8 + j] ^=  whiteKeys[3][j];
        }
        return state;
    }

    public static List<Integer> recoverFromDiff(int[] indiff, int[] outdiff){
        //indf = 4*4bit
        List<Integer> res=  new ArrayList<>();
        for (int i = 0; i < (1<<16); i++) {
            int[] x= toIntArray(i);
            int[] x_s = xorArray(x, indiff);
            int[] F_x = F(x);
            int[] F_xs = F(x_s);
            int[] FoutDiff = xorArray(F_xs, F_x);
            int flag =1;
            for (int j = 0; j < 4; j++) {
                if (outdiff[j] != FoutDiff[j]) {
                    flag = 0;
                    break;
                }
            }
            if(flag == 1)   res.add(i);
        }
        return res;
    }

    public static int[] encrypt_star(int[] state1, int[] key, int fau1, int fau2) {
        // state  = 16 * 4bit
        int[] state = state1.clone();
        int[][] roundKeys = keySchedule(key);
        int[][] whiteKeys = whiteKeySchedule(key);
        for (int j = 0; j < 4; j++) {
            state[j] ^=  whiteKeys[0][j];
            state[8 + j] ^=  whiteKeys[1][j];
        }
        for (int i = 0; i < 25; i++) {
            if(i == 21) {
                state[10] ^= fau1;
                state[11] ^= fau2;
            }
            if (i == 22) {
//                System.out.println();
//                System.out.println();
            }

            int[] fA = F(new int[]{state[0], state[1], state[2], state[3]});
            int[] fC = F(new int[]{state[8], state[9], state[10], state[11]});
//            if(i == 21) {
//                System.out.println(fA[3]);
//            }
            for (int j = 0; j < 4; j++) {
                state[4 + j] ^= fA[j] ^ roundKeys[i][j];
                state[12 + j] ^= fC[j] ^ roundKeys[i][4 + j];
            }

            if(i!= 24) state = rpPermutation(state);
        }
        for (int j = 0; j < 4; j++) {
            state[j] ^=  whiteKeys[2][j];
            state[8 + j] ^=  whiteKeys[3][j];
        }
        return state;
    }

    // Test function
    public static void main(String[] args) throws IOException {
        int[] idiff = new int[]{0x1, 0x1, 0x1, 0x1};
        int[] odiff = new int[]{0x6, 0x6, 0x6, 0x6};
        List<Integer> res=  recoverFromDiff(idiff, odiff);
        System.out.println(res);
//        int[] plaintext = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
//        int[] key = {0x0011, 0x2233, 0x4455, 0x6677, 0x8899};
//        int[] ciphertext1 = encrypt(plaintext, key);
//        int[] ciphertext = encrypt_star(plaintext, key,0,0);
//        System.out.print("Ciphertext: ");
//        for (int b : ciphertext) {
//            System.out.printf("%X ", b);
//        }
    }
}