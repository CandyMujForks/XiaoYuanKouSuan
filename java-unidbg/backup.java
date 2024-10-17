package com.fenbi.android.leo.imgsearch.sdk.utils;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;

public class e {
/*
export LD_LIBRARY_PATH=[放libContentEncoder.so的文件夹路径]:$LD_LIBRARY_PATH
dalvikvm -cp [编译的dex] com.fenbi.android.leo.imgsearch.sdk.utils.e [加密的Base64]
 */
    static {
        System.loadLibrary("ContentEncoder");
    }
    public static native byte[] c(byte[] data);
    public static byte[] a(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            return null;
        }
        byte[] decodedData = b(data);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(decodedData);
             GZIPInputStream gzipIn = new GZIPInputStream(bais)) {
            return gzipIn.readAllBytes();
        }
    }
    public static byte[] b(byte[] data) {
        return c(data);  // 调用 native 库
    }
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("传入命令行参数");
            return;
        }
        try {
            byte[] input = Base64.getDecoder().decode(args[0]);
            byte[] output = a(input);
            if (output != null) {
                System.out.println(new String(output));
            } else {
                System.out.println("解密失败");
            }
        } catch (Exception e) {
            System.out.println("发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
