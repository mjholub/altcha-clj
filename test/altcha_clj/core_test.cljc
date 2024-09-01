(ns altcha-clj.core-test
  (:require
   #?(:clj [clojure.test :as t]
               :cljs [cljs.test :as t])
   [altcha-clj.core :as altcha]
   [altcha-clj.polyfill :refer [now parse-int]]
   [clojure.string :as str]))
#?(:clj
(defn mock-random-bytes [n]
  (byte-array (take n (cycle (range 256)))))
  :cljs 
  (defn mock-random-bytes [n]
    (new js/Unit8Array (take n (cycle (range 256))))
    )
)

(defn mock-random-int [_]
  42)

(t/deftest test-calculate-expiration-offset
  (t/testing "Correctly adds the number of ms"
    (t/is (= 5010 (altcha/calculate-expiration-offset 10 5 false)))
    )
  #?(:clj (t/testing "The result is of type java.lang.Long"
     (t/is (= "class java.lang.Long"
              (str (type (altcha/calculate-expiration-offset 10 5 false)))))
     (t/is (= "class java.lang.Long"
           (str (type (altcha/calculate-expiration-offset 0 15 true))))
           ))
  ))

(t/deftest create-challenge-test
  (with-redefs [altcha/random-bytes mock-random-bytes
                altcha/random-int mock-random-int]
    
    (t/testing "Basic challenge creation"
      (let [challenge (altcha/create-challenge {:hmac-key "test-key"})]
        (t/is (= "SHA-256" (:algorithm challenge)))
        (t/is (string? (:challenge challenge)))
        (t/is (= 1e6 (:maxnumber challenge)))
        (t/is (string? (:salt challenge)))
        (t/is (string? (:signature challenge)))))
    
    (t/testing "Custom algorithm"
      (let [challenge (altcha/create-challenge {:hmac-key "test-key" :algorithm "SHA-512"})]
        (t/is (= "SHA-512" (:algorithm challenge)))))
    
    (t/testing "Custom max number"
      (let [challenge (altcha/create-challenge {:hmac-key "test-key" :max-number 1000})]
        (t/is (= 1000 (:maxnumber challenge)))))
    
    (t/testing "Custom salt"
      (let [challenge (altcha/create-challenge {:hmac-key "test-key" :salt "custom-salt"})]
        (t/is (= "custom-salt" (:salt challenge)))))
    
    (t/testing "Expires parameter" ;; NOTE: in this case as the implementation is
     ;; not 100% pure, we can only do a fuzzy check.
     ;; See the test for `calculate-expiration-offset`
      (let [expires 60
            current-ts (now)
            lowest-correct-expire-ts (+ (* 1000) current-ts)
            challenge (altcha/create-challenge {:hmac-key "test-key" :expires expires})]
        (t/is (<= lowest-correct-expire-ts 
                  (parse-int (last (re-find #"expires=(\d+)" (:salt challenge))))))))
    
    (t/testing "Additional parameters"
      (let [challenge (altcha/create-challenge {:hmac-key "test-key" 
                                                :params {:custom "param" 
                                                         :another "value"}})]
        (t/is (str/includes? (:salt challenge) "custom=param"))
        (t/is (str/includes? (:salt challenge) "another=value"))))
    
    (t/testing "Determint/istic output"
      (let [challenge1 (altcha/create-challenge {:hmac-key "test-key" :salt "fixed-salt" :number 42})
            challenge2 (altcha/create-challenge {:hmac-key "test-key" :salt "fixed-salt" :number 42})]
        (t/is (= challenge1 challenge2))))
    
    (t/testing "Different keys produce different signatures"
      (let [challenge1 (altcha/create-challenge {:hmac-key "key1" :salt "fixed-salt" :number 42})
            challenge2 (altcha/create-challenge {:hmac-key "key2" :salt "fixed-salt" :number 42})]
        (t/is (not= (:signature challenge1) (:signature challenge2)))))))

#?(:cljs
   (t/deftest js-interop-test
     (t/testing "JavaScript interop"
       (let [js-challenge (js->clj (altcha/createChallenge #js {:hmacKey "test-key"
                                                                :expires (js/Date. 1625097600000)
                                                                :params #js {:custom "param"}})
                                   :keywordize-keys true)]
         (t/is (= "SHA-256" (:algorithm js-challenge)))
         (t/is (string? (:challenge js-challenge)))
         (t/is (= 1e6 (:maxnumber js-challenge)))
         (t/is (string? (:salt js-challenge)))
         (t/is (string? (:signature js-challenge)))
         (t/is (str/includes? (:salt js-challenge) "expires=1625097600"))
         (t/is (str/includes? (:salt js-challenge) "custom=param"))))))

#?(:clj
   (defn test-ns-hook []
     (test-calculate-expiration-offset)
     (create-challenge-test))
   :cljs
   (defn ^:export run-tests []
     (cljs.test/run-tests 'altcha-clj.core-test)))
