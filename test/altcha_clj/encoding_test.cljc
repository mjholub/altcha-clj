(ns altcha-clj.encoding-test
    (:require
   #?(:clj [clojure.test :as t]
               :cljs [cljs.test :as t])
    [altcha-clj.encoding :as e]
  )
    
    )

(t/deftest test-encode-params 
  (t/testing "Regular map of string keys with no spaces"
    (t/is (= "k1=foo&k2=bar&k3=baz" (e/encode-params {:k1 "foo" :k2 "bar" :k3 "baz"})))
    )
  (t/testing "Mixed data types"
    (t/is (= "k1=%3Ak2&k3=%5B%3Afoo+%22bar%22+23%5D" 
             (e/encode-params {:k1 :k2 :k3 [:foo "bar" 23]})))
    )
  (t/testing "Single-element map"
    (t/is (= "foo=42" (e/encode-params {:foo 42})))
    )
  (t/testing "Value with spaces"
    (t/is (= "k1=make+room" (e/encode-params {:k1 "make room"})))
    )
(t/testing "Special characters"
  (t/is (= "key1=%21%40%23%24%25%5E%26*%28%29" (e/encode-params {:key1 "!@#$%^&*()"})))
  )
  )

(t/deftest decode-url-component-test
  (t/testing "Decoding url components"
    (t/is (= "value with spaces"
             (e/decode-url-component "value%20with%20spaces")
             ))
    (t/is (= "!@#$%^*()" (e/decode-url-component "%21%40%23%24%25%5E*%28%29")))
    )
  )

(t/deftest extract-params-test
  (t/testing "Extracting parameters from a URL"
    (t/is (= {:key1 "value1" :key2 "value2"} (e/extract-params "key1=value1&key2=value2")))
    (t/is (= {:key1 "value with spaces"} (e/extract-params (e/decode-url-component "key1=value%20with%20spaces"))))
    (t/is (= {:key1 "!@#$%^*()"} (e/extract-params 
                                   (e/decode-url-component "key1=%21%40%23%24%25%5E%2A%28%29"))))
    (t/is (= {:key1 "42"} (e/extract-params "key1=42"))))
  (t/testing "Handling null values"
    (t/is (= {:k0 nil :k1 nil :k2 nil} (e/extract-params "k0=&k1=null&k2=nil")))
    )
  )

(t/deftest decode-base64-test
  (t/testing "Decoding base64 strings"
    (t/is (= "Hello, World!" (e/decode-base64 "SGVsbG8sIFdvcmxkIQ==")))
    (t/is (= "42" (e/decode-base64 "NDI=")))
    (t/is (= "!@#$%^&*()" (e/decode-base64 "IUAjJCVeJiooKQ=="))))

  (t/testing "Decoding base64 strings with padding"
    (t/is (= "Hello, World!" (e/decode-base64 "SGVsbG8sIFdvcmxkIQ"))))

  (t/testing "Decoding empty base64 string"
    (t/is (= "" (e/decode-base64 "")))))

(t/deftest json->clj-test
  (t/testing "Converting JSON to Clojure data structures"
    (t/is (= {:key1 "value1" :key2 "value2"} (e/json->clj "{\"key1\":\"value1\",\"key2\":\"value2\"}")))
    (t/is (= {:key1 42 :key2 true :key3 nil} (e/json->clj "{\"key1\":42,\"key2\":true,\"key3\":null}")))
    (t/is (= [1 2 3] (e/json->clj "[1,2,3]"))))

  (t/testing "Converting malformed JSON"
    (t/is (thrown? #?(:clj Exception
                   :cljs js/Error) (e/json->clj "{"))))

  (t/testing "Converting empty JSON"
    (t/is (= {} (e/json->clj "{}"))
        (t/is (= [] (e/json->clj "[]")))))) 
