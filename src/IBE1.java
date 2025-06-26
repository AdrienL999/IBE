import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public class IBE1 {
    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element x = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(mskProp, mskFileName);

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element g_x = g.duplicate().powZn(x); // g^x
        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pkProp.setProperty("g_x", Base64.getEncoder().encodeToString(g_x.toBytes())); // 保存 g^x
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, String id, 
                             String mskFileName, String skFileName) 
            throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String xString = mskProp.getProperty("x");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();

        Element sk = QID.powZn(x).getImmutable(); // QID^x
        Properties skProp = new Properties();
        skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, String id, 
                              String message, String ctFileName, String pkFileName) 
            throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        
        String g_xString = pkProp.getProperty("g_x");
        // 修正：g_x 是 G1 元素，不是 Zr 元素
        Element g_x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_xString)).getImmutable();

        Element r = bp.getZr().newRandomElement().getImmutable();
        Element C1 = g.duplicate().powZn(r); // g^r
        
        // 计算 e(QID, g_x)^r
        Element gID = bp.pairing(QID, g_x).powZn(r).getImmutable(); 

        // 重要改进：直接使用字节数组，避免字符串转换损坏数据
        byte[] HgID = sha1(gID.toBytes());
        byte[] messageBytes = message.getBytes();
        byte[] C2 = new byte[messageBytes.length];
        for (int i=0; i<messageBytes.length; i++) {
            int hashPos = i % HgID.length;  // 循环使用哈希字节
            C2[i] = (byte) (messageBytes[i] ^ HgID[hashPos]);
        }
//        for (int i = 0; i < messageBytes.length; i++) {
//            C2[i] = (byte) (messageBytes[i] ^ HgID[i % HgID.length]);
//        }

        Properties ctProp = new Properties();
        ctProp.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        ctProp.setProperty("C2", Base64.getEncoder().encodeToString(C2));
        storePropToFile(ctProp, ctFileName);
    }

    public static String decrypt(String pairingParametersFileName, 
                                String skFileName, String ctFileName) 
            throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        // 修正：从密文文件读取密文，而不是从私钥文件
        Properties ctProp = loadPropFromFile(ctFileName);
        String C1String = ctProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        
        String C2String = ctProp.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2String);

        // 计算 e(sk, C1) = e(QID^x, g^r)
        Element gID = bp.pairing(sk, C1).getImmutable();

        // 重要改进：直接使用字节数组
        byte[] HgID = sha1(gID.toBytes());
        byte[] messageBytes = new byte[C2.length];
        for (int i = 0; i < C2.length; i++) {
            messageBytes[i] = (byte) (C2[i] ^ HgID[i % HgID.length]);
        }
        return new String(messageBytes);
    }

    private static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            System.err.println("❌ 加载文件失败: " + fileName);
            System.err.println("错误原因: " + e.getMessage());
            throw new RuntimeException("无法加载配置文件: " + fileName, e);
        }
        return prop;
    }

    private static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(content.getBytes());
        return md.digest();
    }
    
    // 重载方法：直接处理字节数组
    private static byte[] sha1(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try {
            // 确保目录存在
            Path path = Paths.get(fileName);
            Path parentDir = path.getParent();
            
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
                System.out.println("✅ 创建目录: " + parentDir);
            }
            
            // 保存文件
            try (OutputStream out = Files.newOutputStream(path)) {
                prop.store(out, "IBE System Parameters");
                System.out.println("💾 成功保存: " + fileName);
            }
        } catch (IOException e) {
            System.err.println("❌ 保存失败: " + fileName);
            System.err.println("错误详情: " + e.getMessage());
            throw new RuntimeException("无法保存文件: " + fileName, e);
        }
    }

    public static void performanceTest() throws Exception {
        // 测试参数
        String pairingParametersFileName = "a.properties";
        String dir = "data/";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";
        String testID = "test@performance.com";

        // 生成精确长度的测试消息
        String baseMsg = "测试消息1234567890"; // 20字节(UTF-8)
        StringBuilder longMsg = new StringBuilder();
        for(int i=0; i<256; i++) { // 生成5KB左右的消息
            longMsg.append(baseMsg);
        }
        String message = longMsg.toString();

        System.out.println("=== IBE 性能测试开始 ===");
        System.out.printf("测试消息长度: %d 字节\n", message.getBytes().length);

        // 1. Setup阶段性能
        long start = System.nanoTime();
        setup(pairingParametersFileName, pkFileName, mskFileName);
        long setupTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        // 2. KeyGen阶段性能
        start = System.nanoTime();
        keygen(pairingParametersFileName, testID, mskFileName, skFileName);
        long keygenTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        // 3. 加密性能测试
        int[] messageLengths = {64, 256, 1024, 4096}; // 字节
        long[] encryptTimes = new long[messageLengths.length];

        for(int i=0; i<messageLengths.length; i++) {
            byte[] msgBytes = Arrays.copyOf(message.getBytes(), messageLengths[i]);
            String testMsg = new String(msgBytes, "UTF-8");

            start = System.nanoTime();
            encrypt(pairingParametersFileName, testID, testMsg, ctFileName, pkFileName);
            encryptTimes[i] = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        }

        // 4. 解密性能
        start = System.nanoTime();
        String decrypted = decrypt(pairingParametersFileName, skFileName, ctFileName);
        long decryptTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        // 打印结果
        System.out.println("\n【核心操作耗时】");
        System.out.printf("Setup: %d ms\n", setupTime);
        System.out.printf("KeyGen: %d ms\n", keygenTime);
        System.out.printf("Decrypt: %d ms\n", decryptTime);

        System.out.println("\n【加密吞吐量】");
        for(int i=0; i<messageLengths.length; i++) {
            double throughput = (messageLengths[i] * 1000.0) / encryptTimes[i]; // bytes/sec
            System.out.printf("%d字节消息 => %d ms (%.2f KB/s)\n",
                    messageLengths[i], encryptTimes[i], throughput/1024);
        }

        // 内存占用分析
        Runtime runtime = Runtime.getRuntime();
        System.out.println("\n【内存使用】");
        System.out.printf("总内存: %.2f MB\n", runtime.totalMemory() / (1024.0 * 1024));
        System.out.printf("空闲内存: %.2f MB\n", runtime.freeMemory() / (1024.0 * 1024));
    }

    public static void main(String[] args) throws Exception {
        // 确保配对参数文件存在
        String pairingParamsFile = "a.properties";
        File paramFile = new File(pairingParamsFile);
        if (!paramFile.exists()) {
            System.err.println("❌ 配对参数文件不存在: " + paramFile.getAbsolutePath());
            System.err.println("请从 JPBC 库中获取参数文件");
            System.exit(1);
        }

        String idBob = "bob@example.com";
        String idAlice = "alice@example.com";
        String message = "Hello, IBE Encryption! 你好，基于身份的加密！";
        
        // 使用相对路径
        String dir = "data/";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        // 1. 初始化系统
        setup(pairingParamsFile, pkFileName, mskFileName);
        
        // 2. 生成用户密钥（修正参数顺序）
        keygen(pairingParamsFile, idBob, mskFileName, skFileName);
        
        // 3. 加密消息（修正参数顺序）
        encrypt(pairingParamsFile, idBob, message, ctFileName, pkFileName);
        
        // 4. 解密消息
        String decrypted = decrypt(pairingParamsFile, skFileName, ctFileName);
        
        System.out.println("\n=======================================");
        System.out.println("原始消息: " + message);
        System.out.println("解密消息: " + decrypted);
        System.out.println("解密" + (message.equals(decrypted) ? "成功 ✅" : "失败 ❌"));
        System.out.println("=======================================");

        performanceTest();
    }
}