import java.util.*;

public class mitm_dfa extends PiccoloCipher{


    //    static int[] plaintext = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    static int[] plaintext = {14, 6, 1, 10, 9, 15, 13, 6, 6, 10, 8, 11, 8, 3, 11, 5};
    public static int[] key = {0x0011, 0x2233, 0x4455, 0x6677, 0x8899};
    static int[] ciphertext = encrypt(plaintext, key);
    static int[] ciphertext_1 = encrypt_star(plaintext, key,4,2);
    static int[] ciphertext_2 = encrypt_star(plaintext, key,3,7);
    static int[] ciphertext_3 = encrypt_star(plaintext, key,9,8);

    static int[] ciphertext_4 = encrypt_star(plaintext, key,13,6);


    static int[][] ct_all = new int[][]{ciphertext, ciphertext_1, ciphertext_2, ciphertext_3, ciphertext_4};


    public static List<int[]> MITM(){
        int num=0;
        List<int[]> res_m1 = new ArrayList<>();

        // index_-- String c1c2     inside--wk3_imd34_imd12
        for (int wk_3 = 0; wk_3 <= (1<<16); wk_3++) {
            HashMap<String, List<Integer>> L_1 = new HashMap<>();
            int[] wk_3A = toIntArray(wk_3);
            // 4ge 4*4bit
            int[][] F_precom = new int[5][];
            for (int i = 0; i < 5; i++) {
                int[] state = new int[]{ct_all[i][8], ct_all[i][9], ct_all[i][10], ct_all[i][11]};
                F_precom[i] = F(xorArray(state, wk_3A));
            }
            for (int imd34 = 0; imd34 < 256; imd34++) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 1; i++) {
                    for (int j = i+1; j < 5; j++) {
                        sb.append(String.format("%02X", MITM_compute34(F_precom, imd34, i, j)));
                    }
                }
                if (!L_1.containsKey(String.valueOf(sb))){
                    List<Integer> list = new ArrayList<>();
                    list.add(imd34);
                    L_1.put(String.valueOf(sb), list);
                }else{
                    List<Integer> list = L_1.get(String.valueOf(sb));
                    list.add(imd34);
                }
            }
            for (int imd12 = 0; imd12 < 256; imd12++) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 1; i++) {
                    for (int j = i+1; j < 5; j++) {
                        sb.append(String.format("%02X", MITM_compute12(F_precom, imd12, i, j)));
                    }
                }
                String str= String.valueOf(sb);
                if(L_1.containsKey(str)) {
//                    System.out.printf("%02X%n", wk_3);

                    List<Integer> list = L_1.get(String.valueOf(sb));
                    for (int i = 0; i < list.size(); i++) {
                        int imd34 = list.get(i);
                        int[] tempres = new int[4];
                        tempres[0] = wk_3;

                        int[] ct1= ciphertext;
                        int[] F_ct1 = F_precom[0];
                        int state1 = (imd12>>4)^ ct1[12]^ F_ct1[0];
                        int state2 = (imd12 & 0xF)^ ct1[13]^ F_ct1[1];
                        int state3 = (imd34>>4) ^ ct1[14] ^ F_ct1[2];
                        int state4 = (imd34 & 0xF) ^ ct1[15] ^ F_ct1[3];
                        int[] ab22 = F_1(new int[]{state1, state2, state3, state4});
                        tempres[1] = (ab22[0]<<4)^(ab22[1]);
                        tempres[2] = (ab22[2]<<4)^(ab22[3]);

                        int[] ct1s= ciphertext_1;
                        int[] F_ct1s = F_precom[1];
                        int state1s = (imd12>>4)^ ct1s[12]^ F_ct1s[0];
                        int state2s = (imd12 & 0xF)^ ct1s[13]^ F_ct1s[1];
                        int state3s = (imd34>>4) ^ ct1s[14] ^ F_ct1s[2];
                        int state4s = (imd34 & 0xF) ^ ct1s[15] ^ F_ct1s[3];
                        int[] a22s = F_1(new int[]{state1s, state2s, state3s, state4s});
                        tempres[3] = (a22s[2]<<4)^(a22s[3]);
//                  a_22[0] = 0x0009  a_22[1] = 0x000E;
                        res_m1.add(tempres);
                        num++;
                    }


                }
            }

        }
//        System.out.println(num);
        return res_m1;
    }

    public static int MITM_compute34(int[][] F_precom, int imd, int i, int j) {
        int[] ct1 = ct_all[i];
        int[] ct2 = ct_all[j];
        int[] F_ct1 = F_precom[i];
        int[] F_ct2 = F_precom[j];

        int state3 = (imd>>4) ^ ct1[14] ^ F_ct1[2];
        int state3_star = (imd >>4) ^ ct2[14] ^ F_ct2[2];
        int Delta_3 = 0;
        try {
            Delta_3 = S_BOX_1[state3] ^ S_BOX_1[state3_star];
        } catch (Exception e) {
            System.out.println("发生异常: " + e.getMessage());
            System.out.println(state3_star);

            System.out.println(state3);
            e.printStackTrace();
        }

        int state4 = (imd & 0xF) ^ ct1[15] ^ F_ct1[3];
        int state4_star = (imd & 0xF) ^ ct2[15] ^ F_ct2[3];
        int Delta_4 = S_BOX_1[state4] ^ S_BOX_1[state4_star];

        int res_3 = gfMultiply(10, Delta_3) ^ gfMultiply(6, Delta_4);
        int res_4 = Delta_3 ^ Delta_4;
        return (res_3 << 4) ^ res_4;
    }

    public static int MITM_compute12(int[][] F_precom, int imd, int i, int j){
        int[] ct1 = ct_all[i];
        int[] ct2 = ct_all[j];
        int[] F_ct1 = F_precom[i];
        int[] F_ct2 = F_precom[j];

        int state1 = (imd>>4)^ ct1[12]^ F_ct1[0];
        int state1_star = (imd>>4)^ ct2[12]^F_ct2[0];
        int Delta_1 = S_BOX_1[state1]^S_BOX_1[state1_star];

        int state2 = (imd & 0xF)^ ct1[13]^ F_ct1[1];
        int state2_star = (imd & 0xF)^ ct2[13]^F_ct2[1];
        int Delta_2 = S_BOX_1[state2]^S_BOX_1[state2_star];

        return (Delta_1<<4)^Delta_2;
    }

    public static int MITM_compute_S_F23(int[][] F_precom, int k1R, int i){
        //k1R 实际为 rk49R
        int[] ct1 = ct_all[i];

        int[] F_ct1 = F_precom[i];

        int f23_0 = (k1R>>4) ^ ct1[14] ^ F_ct1[2];

        int S_f23_0 = S_BOX[f23_0];

        int f23_1 = (k1R & 0xF) ^ ct1[15] ^ F_ct1[3];
        int S_f23_1 = S_BOX[f23_1];
        return (S_f23_0<< 4) ^ S_f23_1;
    }

    public static int MITM_compute_S1_mn23( int wk3, int a22,  int imd_n, int k4_L, int i){
        int[] ct1 = ct_all[i];

        int m0 = (k4_L>>4) ^ ct1[8] ^ (wk3 >>12) ^ (a22 >>4) ^ 0x4;
        int m1 = (k4_L & 0xF) ^ ct1[9] ^ ((wk3 >>8)&0xF) ^ (a22 & 0xF) ^ 0xD ;

        int n0 = (imd_n>>4) ^ ct1[2];
        int n1 = (imd_n & 0xF) ^ ct1[3];

        int S_m0 = S_BOX_1[m0];
        int S_m1 = S_BOX_1[m1];
        int S_n0 = S_BOX_1[n0];
        int S_n1 = S_BOX_1[n1];

        int[] res_A = pLayer_1(new int[]{S_m0, S_m1, S_n0, S_n1});

        return (res_A[2]<< 4) ^ res_A[3];
    }
    public static List<int[]> MITM_2(int wk3, int a22L){
        List<int[]> res_m2 = new ArrayList<>();
        HashMap<String, List<Integer>> L_1 = new HashMap<>();
        //预先计算F(c+wk3)
        int[] wk_3A = toIntArray(wk3);
        int[][] F_precom = new int[5][];
        for (int i = 0; i < 5; i++) {
            int[] state = new int[]{ct_all[i][8], ct_all[i][9], ct_all[i][10], ct_all[i][11]};
            F_precom[i] = F(xorArray(state, wk_3A));
        }
        for (int rk49R = 0; rk49R < 256; rk49R++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 3; i++) {
                sb.append(String.format("%02X", MITM_compute_S_F23(F_precom, rk49R, i)));
            }
            if(!L_1.containsKey(String.valueOf(sb))){
                List<Integer> list = new ArrayList<>();
                list.add(rk49R);
                L_1.put(String.valueOf(sb), list);
            }else{
                List<Integer> list = L_1.get(String.valueOf(sb));
                list.add(rk49R);
            }

        }
        for (int imd_n = 0; imd_n < 256; imd_n++) {
            for (int k4_l = 0; k4_l < 256; k4_l++) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 3; i++) {
                    sb.append(String.format("%02X", MITM_compute_S1_mn23(wk3, a22L, imd_n, k4_l, i)));
                }
                String str = String.valueOf(sb);
                if (L_1.containsKey(str)){
                    List<Integer> list = L_1.get(String.valueOf(sb));
                    for (int i = 0; i < list.size(); i++) {
                        int[] tempres = new int[4];
                        tempres[0] = k4_l;
                        int k1R = list.get(i)^0x25;
                        tempres[1] = k1R;

                        //n23
                        int[] ct1 = ct_all[0];
                        int m0 = (k4_l>>4) ^ ct1[8] ^ (wk3 >>12) ^ (a22L >>4) ^ 0x4;
                        int m1 = (k4_l & 0xF) ^ ct1[9] ^ ((wk3 >>8)&0xF) ^ (a22L & 0xF) ^ 0xD ;
                        int n0 = (imd_n>>4) ^ ct1[2];
                        int n1 = (imd_n & 0xF) ^ ct1[3];
                        int[] l23 = F_1(new int[]{m0,m1,n0,n1});

                        //n23s
                        int[] ct1s = ct_all[1];
                        int m0s = (k4_l>>4) ^ ct1s[8] ^ (wk3 >>12) ^ (a22L >>4) ^ 0x4;
                        int m1s = (k4_l & 0xF) ^ ct1s[9] ^ ((wk3 >>8)&0xF) ^ (a22L & 0xF) ^ 0xD ;
                        int n0s = (imd_n>>4) ^ ct1s[2];
                        int n1s = (imd_n & 0xF) ^ ct1s[3];
                        int[] l23s = F_1(new int[]{m0s,m1s,n0s,n1s});
                        int Delta_b24L = ((l23[0]^l23s[0])<<4)^(l23[1]^l23s[1]);
                        int delta_CbL = ((ct1[4]^ct1s[4])<<4)^(ct1[5]^ct1s[5]);
                        // delta j 24L
                        tempres[2] = Delta_b24L^delta_CbL;
                        int b24L = (l23[0]<<4)^(l23[1]);
                        tempres[3] = b24L;
                        res_m2.add(tempres);
                    }


                }
            }
        }
        return res_m2;
    }

    public static List<int[]> test_num(int d_j24_L, int b24L, int k4_l) {
        int dy = d_j24_L;
        List<int[]> res_3= new ArrayList<>();
        int res_num =0;

        int[] ct1 = ct_all[0];
        int[] ct1s = ct_all[1];
        for (int x1 = 0; x1 < 16; x1++) {
            for (int x2 = 0; x2 < 16; x2++) {
                int[] Fx = F(new int[]{ct1[0]^(k4_l>>4), ct1[1]^(k4_l&0xF), ct1[2]^x1, ct1[3]^x2});
                int[] Fxs = F(new int[]{ct1s[0]^(k4_l>>4), ct1s[1]^(k4_l&0xF), ct1s[2]^x1, ct1s[3]^x2});
                int[] res = xorArray(Fx, Fxs);
                int res1 = (res[0] << 4)^(res[1]);
                if(res1 == dy) {
                    res_num++;
                    int wk2R = (x1<<4)^x2;
                    int rk48L = ((Fx[0]<<4)^Fx[1])^(b24L)^(ct1[4]<<4)^(ct1[5]);
                    int k0L = rk48L^0xc7;

                    int[] temp =new int[]{wk2R, k0L};
                    res_3.add(temp);
//                    System.out.printf("%02X%n", wk2R);
//                    System.out.printf("%02X%n", k0L);

                }
            }
        }
//        System.out.println(res_num);
        return res_3;
    }

    public static List<int[]> test_num2(int b23R, int b23sR, int wk2, int wk3) {

        int res_num =0;
        List<int[]> res_all =new ArrayList<>();

        int[] ct = ct_all[0];
        int[] cts = ct_all[1];
        int[] j24 = F(new int[]{ct[0]^(wk2>>12), ct[1]^(wk2>>8)& 0xF, ct[2]^(wk2>>4)& 0xF, ct[3]^wk2& 0xF});
        int[] j24s = F(new int[]{cts[0]^(wk2>>12), cts[1]^(wk2>>8)& 0xF, cts[2]^(wk2>>4)& 0xF, cts[3]^wk2& 0xF});
        int d_j24_R = ((j24[2]^j24s[2])<<4)^(j24[3]^j24s[3]);
        int d_a23_R = d_j24_R ^ ((ct[6]^cts[6])<<4) ^ (ct[7]^cts[7]);

        int[] n24 = F(new int[]{ct[8]^(wk3>>12), ct[9]^(wk3>>8)& 0xF, ct[10]^(wk3>>4)& 0xF, ct[11]^wk3& 0xF});
        int[] n24s = F(new int[]{cts[8]^(wk3>>12), cts[9]^(wk3>>8)& 0xF, cts[10]^(wk3>>4)& 0xF, cts[11]^wk3& 0xF});
        int d_n24_L = ((n24[0]^n24s[0])<<4)^(n24[1]^n24s[1]);
        int d_a23_L = d_n24_L ^ ((ct[12]^cts[12])<<4) ^ (ct[13]^cts[13]);
        int d_a23 = (d_a23_L<<8)^(d_a23_R);

//        int rk46L = (wk2>>8)^0xcf;
//        int rk46R = (wk3 ^ 0xFF)^0x2e;
//        int wk2L = (wk2>>8);
//        int wk3R =
        int j23L__ = 0xcf ^ (ct[0]<<4) ^ (ct[1]);
        int j23sL__ = 0xcf ^ (cts[0]<<4) ^ (cts[1]);
        int j23R__ = 0x2e ^ b23R ^ (ct[10]<<4) ^ (ct[11]);
        int j23sR__ = 0x2e ^ b23sR ^ (cts[10]<<4) ^ (cts[11]);

        for (int b23L = 0; b23L < 256; b23L++) {
            for (int in2 = 0; in2 < 256; in2++) {
                int j23 = ((j23L__ ^ b23L)<<8) ^ j23R__;
                int j23s = ( (j23sL__ ^ in2)<<8 )^ j23sR__;
                int[] Fx = F_1( toIntArray(j23) );
                int[] Fxs = F_1(toIntArray(j23s));
                int[] res = xorArray(Fx, Fxs);
                int res1 = (res[0] << 12)^(res[1] << 8)^(res[2] << 4)^(res[3]);
                if(res1 == d_a23) {
                    res_num++;
                    int[] tempres =  new int[2];

                    int[] a23 = Fx;
                    int rk48R = (a23[2]<<4)^a23[3] ^ (ct[6]<<4)^ct[7] ^ (j24[2]<<4)^j24[3];
                    int rk49L = (ct[12]<<4)^ct[13] ^ (a23[0]<<4)^a23[1] ^ (n24[0]<<4)^n24[1];
                    int k0R = rk48R ^ 0x2c;
                    int k1L = rk49L ^ 0x49;
                    tempres[0] = k0R;
                    tempres[1] = k1L;
                    res_all.add(tempres);
                }
            }
        }
//        System.out.println(res_num);
        return res_all;
    }

    public static List<int[]> check() {
        List<int[]> res_m1= MITM();
        System.out.println("步骤 2 的候选结果数量为： "+res_m1.size());
//        System.out.println(res_m1.size());

        List<int[]> res_m2 = new ArrayList<>();
        for (int i = 0; i < res_m1.size(); i++) {
            int[] res1 = res_m1.get(i);
            int wk3 = res1[0];
            int a22l = res1[1];
            List<int[]> m2 = MITM_2(wk3, a22l);
            for (int j = 0; j < m2.size(); j++) {
                int[] resm2 = m2.get(j);
                int[] temp = new int[7];
                temp[0] = res1[0];
                temp[1] = res1[2];
                temp[2] = res1[3];
                temp[3] = resm2[0];
                temp[4] = resm2[1];
                temp[5] = resm2[2];
                temp[6] = resm2[3];
                res_m2.add(temp);
            }
        }
        System.out.println("步骤 3 的候选结果数量为： "+res_m2.size());
//        System.out.println(res_m2.size());
        //wk3 a22r a22r* k4L k1R d_j_24L b24L


        List<int[]> res_3 = new ArrayList<>();
        for (int i = 0; i < res_m2.size(); i++) {
            int[] res2 = res_m2.get(i);
            int wk2L = res2[3];
            int d_j24L = res2[5];
            int b24L = res2[6];
            List<int[]> res3 = test_num(d_j24L,b24L,wk2L);
            for (int j = 0; j < res3.size(); j++) {
                int wk3 = res2[0];
                int a22r = res2[1];
                int a22rs = res2[2];
                int wk2 = (wk2L<<8)^(res3.get(j)[0]);
                int k0L = res3.get(j)[1];
                int k1R = res2[4];
                res_3.add(new int[]{wk3, wk2, k0L, k1R, a22r, a22rs});
            }
        }
        System.out.println("步骤 4 使用单密文对的候选结果数量为：  "+res_3.size());
//        System.out.println(res_3.size());

        int flag =-1;

        List<int[]> res_4 = new ArrayList<>();
        for (int i = 0; i < res_3.size(); i++) {
            int[] tres3 = res_3.get(i);
            int wk3 = tres3[0];
            int wk2 = tres3[1];
            int k0L = tres3[2];
            int k1R = tres3[3];
            int a22r = tres3[4];
            int a22sr = tres3[5];
            List<int[]> tres4 = test_num2(a22r, a22sr, wk2, wk3);
            for (int j = 0; j < tres4.size(); j++) {
                int k0 = (k0L<<8) ^ tres4.get(j)[0];
                int k1 = (tres4.get(j)[1]<<8) ^ k1R;
                int k3 = (wk3 & 0xFF00) ^ (wk2 & 0x00FF);
                int k4 = (wk2 & 0xFF00) ^ (wk3 & 0x00FF);
                res_4.add(new int[]{k0, k1, k3, k4});
//                if(k0 == 0x11 && k1 == 0x2233 && k3 == 0x6677 && k4 == 0x8899)  flag =1;
//                System.out.println("all is end?");
//                System.out.printf("%04X%n", k0);
//                System.out.printf("%02X%n", k1);
//                System.out.printf("%02X%n", k3);
//                System.out.printf("%02X%n", k4);
            }
        }
//        System.out.println("AFTER ALL is "+ res_4.size());
//        if(flag == -1) {
//            System.out.println("BADHAPPEN!");
//            return -1;
//        }
        System.out.println("步骤 5 使用单密文对的候选结果数量为：  "+res_4.size());
        return res_4;


//        MITM_2(0x6699, 0x9E);



//        System.out.print("Ciphertext: ");
//        for (int b : ciphertext) {
//            System.out.printf("%X ", b);
//        }
//        System.out.println();
//        System.out.print("Ciphertext_star: ");
//        for (int b : ciphertext_star) {
//            System.out.printf("%X ", b);
//        }
    }

    public static int[] generateRandomArray(int size, int min, int max) {
        Random random = new Random();
        int[] array = new int[size];
        for (int i = 0; i < size; i++) {
            array[i] = random.nextInt(max - min + 1) + min;
        }
        return array;
    }

    public static void main1(String[] args) {
//        int[] nums = new int[10000];
        for (int i = 0; i < 1; i++) {
            plaintext = generateRandomArray(16, 0, 15);
            ciphertext = encrypt(plaintext, key);
            ciphertext_1 = encrypt_star(plaintext, key,4,2);
            ciphertext_2 = encrypt_star(plaintext, key,3,7);
            ciphertext_3 = encrypt_star(plaintext, key,9,8);
            ciphertext_4 = encrypt_star(plaintext, key,13,6);
            ct_all = new int[][]{ciphertext, ciphertext_1, ciphertext_2, ciphertext_3, ciphertext_4};
            List<int[]> a = check();

            System.out.println(a);

//            if(a == -1){
//                System.out.println("badbadbad");
//                return;
//            }
//            nums[a]++;
        }
//        for (int i = 0; i < nums.length; i++) {
//            if(nums[i] != 0){
//                System.out.println("num "+i+" is: "+nums[i]);
//            }
//        }

    }

    public static void main(String[] args) {
        int[] nums = new int[10000];
            plaintext = generateRandomArray(16, 0, 15);

            Scanner scanner = new Scanner(System.in);
            System.out.println("请输入20个十六进制数字作为密钥（每个0~F，每四位以空格分隔，如：1234 5678 9ABC DEF0 1234）：");
            String[] input = scanner.nextLine().trim().split("\\s+");

            if (input.length != 5) {
                System.out.println("输入数量不正确，必须是20个十六进制数字！");
                return;
            }

            try {
                for (int i = 0; i < 5; i++) {
                    int value = 0;
                    for (int j = 0; j < 4; j++) {
                        int digit = Integer.parseInt(input[i], 16);
                        value = digit;  // 每个数字占4位
                    }
                    key[i] = value;
                }
            } catch (NumberFormatException e) {
                System.out.println("输入包含非法十六进制字符，请仅输入0~F。");
                return;
            }
        long startTime=System.currentTimeMillis();   //获取开始时间


        ciphertext = encrypt(plaintext, key);
            ciphertext_1 = encrypt_star(plaintext, key,4,2);
            ciphertext_2 = encrypt_star(plaintext, key,3,7);
            ciphertext_3 = encrypt_star(plaintext, key,9,8);
            ciphertext_4 = encrypt_star(plaintext, key,13,6);
            ct_all = new int[][]{ciphertext, ciphertext_1, ciphertext_2, ciphertext_3, ciphertext_4};
            List<int[]> a = check();
        for (int i = 0; i < a.size(); i++) {
            int[] cpm_res = a.get(i);
            if(cpm_res[0] == key[0] && cpm_res[1] == key[1] && cpm_res[2] == key[3] && cpm_res[3] == key[4]) {
                System.out.println("密钥恢复成功!");
                long endTime=System.currentTimeMillis(); //获取结束时间
                System.out.println("程序运行时间： "+(endTime-startTime)+"ms");

//                for (int j = 0; j < 256*256; j++) {
//                    ciphertext = encrypt(plaintext, key);
//                }
//                long endTime2=System.currentTimeMillis();
//                System.out.println("程序运行时间： "+(endTime2-endTime)+"ms");
                return;
            }
        }


    }
}
