import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;

//将文件转换成字节码
public class tool {
    public static void main(String[] args){
        var fun = new Fun();
        byte[] kk = fun.fileConvertToByteArray(new File("src/TestExp.java"));
        System.out.println(Arrays.toString(kk));
    }

}


class Fun{
    public byte[] fileConvertToByteArray(File file) {
        byte[] data = null;
        ByteArrayOutputStream baos;
        FileInputStream fis;
        try {
            fis = new FileInputStream(file);
            baos = new ByteArrayOutputStream();

            int len;
            byte[] buffer = new byte[1024];
            while ((len = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            data = baos.toByteArray();

            fis.close();
            baos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return data;
    }
}




