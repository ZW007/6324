
import java.io.*;

public class RandomAccessFileDemo {
   public static void main(String[] args) {

      try {
         byte[] b1 = {15, 8, 23};
         
         // create a new RandomAccessFile with filename test
         RandomAccessFile raf = new RandomAccessFile("test.txt", "rw");

         // write something in the file
         raf.writeByte(b1[0]);

         // set the file pointer at 0 position
         raf.seek(0);

         // read byte
         System.out.println("" + raf.readByte());

         // set the file pointer at 0 position
         raf.seek(1);

         // write 0 at the start
         raf.writeByte(b1[1]);
         raf.writeByte(b1[2]);

         // set the file pointer at 0 position
         raf.seek(1);

         // read byte
         System.out.println("" + raf.readByte());
                  System.out.println("" + raf.readByte());

         
      } catch (IOException ex) {
         ex.printStackTrace();
      }
   }
}