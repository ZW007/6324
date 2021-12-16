public class test{

    // do not use a = 0, str.equals("NUL") wont work
    public static void main(String []args) {
         byte a = 64;
        char b = (char) a;
       System.out.println(b); 
      String str = Character.toString(b);
       if(str.equals("@")){
         System.out.println("byte 64 to char will be @ bcz ASCII 64 is @"); 
       }

       char charnum = '0';
       byte bytenum = (byte) charnum;
       System.out.println(bytenum); 
    }
}

