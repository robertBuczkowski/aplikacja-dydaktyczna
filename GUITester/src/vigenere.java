 class vigenere {

        static String generateKey(String str, String key)
        {
            int x = str.length();
            StringBuilder keyBuilder = new StringBuilder(key);
            for (int i = 0; ; i++)
            {
                if (x == i)
                    i = 0;
                if (keyBuilder.length() == str.length())
                    break;
                keyBuilder.append(keyBuilder.charAt(i));
            }
            key = keyBuilder.toString();
            return key;
        }

        static String cipherText(String str, String key)
        {
            String cipher_text = "";
            for (int i = 0; i < str.length(); i++)
            {
                int x = (str.charAt(i) + key.charAt(i)) %26;
                x += 'A';
                cipher_text+=(char)(x);
            }
            return cipher_text;
        }


        static String originalText(String cipher_text, String key)
        {
            String orig_text="";
            for (int i = 0 ; i < cipher_text.length() &&
                    i < key.length(); i++)
            {
                int x = (cipher_text.charAt(i) -
                        key.charAt(i) + 26) %26;
                x += 'A';
                orig_text+=(char)(x);
            }
            return orig_text;
        }
    }
