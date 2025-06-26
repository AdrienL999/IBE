import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

public class IBE {
    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element x = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();//创建一个Properties对象，用于管理键值对（key-value pairs）配置数据。
        //mskProp.setProperty("x", x.toBigInteger().toString());   //x有toBigInteger方法，因此可以用这种方式，但g不能
        //后面对写的元素统一采用如下方法：首先将元素转为字节数组，然后进行Base64编码为可读字符串
        mskProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(mskProp,mskFileName);
        //x.toBytes(): 将 JPBC 的 Element（数学元素）转换为 二进制字节数组（byte[]）
        //Base64.getEncoder().encodeToString(): 将字节数组转换成 Base64 编码的字符串（避免乱码）。
        //mskProp.setProperty("x", ...): 以 "x" 为 key，把 Base64 字符串存入 Properties 方便写入 .properties 文件。

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element g_x = g.duplicate().powZn(x);
        Properties pkProp = new Properties();
        //pkProp.setProperty("g", new String(g.toBytes()));  //可以用这种方式将g转换为字符串后写入，但文件中显示乱码
        //为了避免乱码问题，采用Base64编码方式
        pkProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pkProp.setProperty("g_x", Base64.getEncoder().encodeToString(g_x.toBytes()));
        storePropToFile(pkProp,pkFileName);
    }

    public static void keygen(String pairingParametersFileName, String id, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        //throws NoSuchAlgorithmException是因为该方法内部调用了可能抛此异常的安全算法操作（比如 SHA-1 哈希计算）
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        byte[] idHash = sha1(id);//调用sha1计算id的哈希值
        Element QID = bp.getG1().newElement().setFromHash(idHash, 0, idHash.length).getImmutable();//这两行代码实现的是H1函数，从将任意二进制数据映射到G1

        Properties mskProp = loadProPFromFile(mskFileName);
        String xString =mskProp.getProperty("x");//如果要整形。int x = Integer.parseInt(xString);
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();
        //Base64.getDecoder() 返回一个 Base64 解码器对象，支持标准 Base64 编码（RFC 4648）
        //.decode(xString) 执行具体解码逻辑，输入：Base64 编码的字符串（如 "SGVsbG8="） 输出：原始字节数组（byte[]）

        Element sk = QID.powZn(x).getImmutable();
        Properties skProp = new Properties();
        skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(skProp,skFileName);
    }

    public static void encrypt(String pairingParametersFileName, String id, String message, String ctFileName, String pkFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();//这两行代码实现的是H1函数，从将任意二进制数据映射到G1

        Properties pkProp = loadProPFromFile(pkFileName);//从文件中读取出pk
        String gString =pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_xString =pkProp.getProperty("g_x");
        Element g_x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_xString)).getImmutable();

        Element r = bp.getZr().newRandomElement().getImmutable();
        Element C1= g.duplicate().powZn(r);
        Element gID = bp.pairing(QID, g_x).powZn(r).getImmutable(); //计算gID

        //重要部分
        String gIDString = new String(gID.toBytes()); // 将GT群中的gID字节数组转为字符串（可能不安全）
        byte[] HgID = sha1(gIDString); // 将gID的字节数组转为字符串（可能不安全），实现H2函数
        byte[] messageByte = message.getBytes(); //将消息 message 转为字节数组（messageByte）。
        byte[] C2 = new byte[messageByte.length]; //创建等长的空数组 C2，存储加密结果。
        for (int i=0; i<messageByte.length; i++) {
            C2[i] = (byte) (messageByte[i] ^ HgID[i]); //对每个字节执行 messageByte[i] XOR HgID[i]，结果存入 C2。
        }

        Properties ctProp = new Properties();
        ctProp.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        ctProp.setProperty("C2",Base64.getEncoder().encodeToString(C2));
        storePropToFile(ctProp,ctFileName);
    }

    public static String decrypt(String pairingParametersFileName, String skFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        //先把sk取出来
        Properties skProp = loadProPFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        //取C1
        Properties ctProp = loadProPFromFile(ctFileName);
        String C1String = ctProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        String C2String = ctProp.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2String);

        Element gID = bp.pairing(sk, C1).getImmutable();

        String gIDString = new String(gID.toBytes());
        byte[] HgID = sha1(gIDString);
        byte[] M =new byte[C2.length];
        for (int i=0; i<C2.length; i++) {
            M[i] = (byte) (C2[i] ^ HgID[i]);
        }
        return new String(M);
    }

    private static Properties loadProPFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.err.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    private static byte[] sha1(String content) throws NoSuchAlgorithmException { //计算字符串的 SHA-1 哈希值
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // 1. 获取 SHA-1 算法的 MessageDigest 实例
        md.update(content.getBytes()); // 2. 将字符串转为字节数组，并送入哈希计算引擎
        return md.digest();// 3. 完成计算并返回哈希结果（20 字节）
    }

//    private static void storePropToFile(Properties prop, String fileName) {
//        // 检查输入参数是否合法
//        if(prop == null || fileName == null || fileName.isEmpty()) {
//            throw new NullPointerException("Properties 或文件名不能为空！");
//        }
//
//        try (FileOutputStream out = new FileOutputStream(fileName)) { // 1. 尝试创建文件输出流
//            // // 2. 将属性内容写入文件
//            // 通过 try-with-resources 语法（try(FileOutputStream out = ...)）自动创建并管理文件输出流。
//            //无论代码是否异常，流都会在结束时自动关闭，避免资源泄漏。
//            prop.store(out, null);
//        } catch (IOException e) {  // 3. 捕获写入过程中的异常
//            System.err.println("❌ 保存文件失败: " + fileName);
//            System.err.println("错误原因: " + e.getMessage());
//            throw new RuntimeException("无法保存配置文件: " + fileName, e);
//        }
//    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }


    public static void main (String[] args) throws Exception{

        String idBob = "bob@example.com";
        String idAlice = "alice@example.com";
        String message = "iii";

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName);

        keygen(pairingParametersFileName, idAlice, mskFileName, skFileName);

        encrypt(pairingParametersFileName, idAlice, message, ctFileName, pkFileName);

        String M = decrypt(pairingParametersFileName, skFileName, ctFileName);

        System.out.println(M);

    }
}


