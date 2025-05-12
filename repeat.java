import java.util.List;
import java.util.Scanner;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class repeat extends mitm_dfa{
    public static void main(String[] args) throws IOException {
        int[] time_nums = new int[100000];
        int repeat_times = 2;
        BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"));
        writer.write("程序运行时间（ms） | 步骤2结果数量 | 步骤3结果数量");
        writer.newLine(); // 换行
        for (int l = 0; l < repeat_times; l++) {
            plaintext = generateRandomArray(16, 0, 15);
            long startTime = System.currentTimeMillis();   //获取开始时间
            ciphertext = encrypt(plaintext, key);
            ciphertext_1 = encrypt_star(plaintext, key, 4, 2);
            ciphertext_2 = encrypt_star(plaintext, key, 3, 7);
            ciphertext_3 = encrypt_star(plaintext, key, 9, 8);
            ciphertext_4 = encrypt_star(plaintext, key, 13, 6);
            ct_all = new int[][]{ciphertext, ciphertext_1, ciphertext_2, ciphertext_3, ciphertext_4};
            List<int[]> a = check();
            System.out.println(buzhou2);
            System.out.println(buzhou3);
            for (int i = 0; i < a.size(); i++) {
                int[] cpm_res = a.get(i);
                if (cpm_res[0] == key[0] && cpm_res[1] == key[1] && cpm_res[2] == key[3] && cpm_res[3] == key[4]) {
                    System.out.println("密钥恢复成功!");
                    long endTime = System.currentTimeMillis(); //获取结束时间
                    System.out.println("程序运行时间： " + (endTime - startTime) + "ms");
                        // 写入第二行：a1 b1 c1
                        writer.write( (endTime - startTime)+ " " + buzhou2 + " " + buzhou3);
                        writer.newLine(); // 可选：末尾再换一行
                        writer.flush();
                }
            }
        }
        writer.close();

    }
}
