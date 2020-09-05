
    public class StringValidation{
        public static boolean validtaeString(String str) {
            str = str.toLowerCase();
            char[] charArray = str.toCharArray();
            for (int i = 0; i < charArray.length; i++) {
                char ch = charArray[i];
                if (!((ch >= '0') && ch <= '1')) {
                    return false;
                }
            }
            return true;
        }
}
