(ns altcha-clj.verification-test
  (:require
   [clojure.test :as t]
   [altcha-clj.core :refer [create-challenge hash-hex hmac-hex]]
   [altcha-clj.encoding :refer [clj->json encode-base64 encode-params]]
   [altcha-clj.verify :as v]
   [altcha-clj.encoding :as enc]))

(def mock-hmac-key "test key")

(t/deftest test-signature-not-expired
  (t/testing "Returns true for :expire > current time"
    (let [mock-verification-data {:expires "150"}]
      (t/is (true? (v/signature-not-expired? mock-verification-data 100))))))

(t/deftest verify-server-signature-test
  (t/testing "Returns a positive verification result
    for good input data that is encoded as a clj map"
    (let [test-time (System/currentTimeMillis)
          expire (str (+ 15000 test-time))
          verification-data (encode-params {:email "čžýěžě@sfffd.net"
                                            :expires expire
                                            :verified "true"
                                            :time (str test-time)})
          signature (hmac-hex "SHA-256" (hash-hex "SHA-256" verification-data) mock-hmac-key)
          payload {:algorithm "SHA-256"
                   :verified true
                   :signature signature
                   :verification-data verification-data}
          result (v/verify-server-signature payload mock-hmac-key)]
      (t/is (true? (:verified result))))))

(def payload-common {:algorithm "SHA-256"
                     :number 420
                     :salt "LoremIpsum"})

(defn- create-b64-payload [challenge]
  (-> (assoc payload-common
             :challenge (:challenge challenge)
             :signature (:signature challenge))
      (clj->json)
      (encode-base64)))

(t/deftest test-check-solution-base64
  (t/testing "Verifies a base64 encoded solution with good values"
    (let [challenge (enc/encode-base64 (enc/clj->json (create-challenge (assoc payload-common
                                                                               :hmac-key mock-hmac-key))))]
      (t/is (true? (v/check-solution-base64 challenge mock-hmac-key false {:number 420})))))
  (t/testing "Challenge created with max-number parameter set"
    (let [challenge (enc/encode-base64 (enc/clj->json (create-challenge (assoc payload-common
                                                                               :max-number 9000
                                                                               :hmac-key mock-hmac-key))))]
      (t/is (true? (v/check-solution-base64 challenge mock-hmac-key false {:number 420})))))

  (t/testing "With expiration"
    (let [;; set expiration time to 90s
          current-time (System/currentTimeMillis)
          challenge (enc/encode-base64 (enc/clj->json (create-challenge (assoc payload-common :hmac-key mock-hmac-key
                                                                               :current-time current-time
                                                                               :expires (+ current-time 90000)))))]
      (t/is (true? (v/check-solution-base64 challenge mock-hmac-key true
                                            {:reference-time current-time
                                             :number 420})))))

  (t/testing "(REGRESSION/integration): trimming params from salt/real world response"
    (let [reference-time 1766152599314
          challenge-base64 (enc/encode-base64 (enc/clj->json (create-challenge {:algorithm "SHA-256"
                                                                                :hmac-key "testkey"
                                                                                :number 1234
                                                                                :expires 1766152609314
                                                                                :current-time reference-time})))
          result (v/check-solution-base64 challenge-base64
                                          "testkey"
                                          true
                                          {:number 1234
                                           :reference-time reference-time
                                           :throw-on-false? false})]

      (t/is (true? result)))))

(t/deftest test-check-solution
  (t/testing "should not verify manipulated (spliced) salt with expires parameter"
    (let [ch (create-challenge {:hmac-key "testkey"
                                :number 123
                                :expires (+ 600 (System/currentTimeMillis))})]
      (t/is false? (v/check-solution {:algorithm (:algorithm ch)
                                      :challenge (:challenge ch)
                                      :number 23
                                      :salt (str (:salt ch) "1")
                                      :signature (:signature ch)}
                                     "testkey"
                                     true)))))
