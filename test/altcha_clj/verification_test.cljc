(ns altcha-clj.verification-test
  (:require
   #?(:clj [clojure.test :as t]
               :cljs [cljs.test :as t])
   [altcha-clj.core :refer [create-challenge hash-hex hmac-hex]]
   [altcha-clj.encoding :refer [clj->json encode-base64 encode-params]]
   [altcha-clj.polyfill :refer [now]]
   [altcha-clj.verify :as v]))

(def mock-hmac-key "test key")

(t/deftest test-signature-not-expired 
  (t/testing "Returns true for :expire > current time"
    (let [mock-verification-data {:expires "150"}]
      (t/is (true? (v/signature-not-expired? mock-verification-data 100)))
      )
    )
  )

(t/deftest verify-server-signature-test 
  (t/testing "Returns a positive verification result
    for good input data that is encoded as a clj map"
    (let [test-time (now)
          expire (str (+ 15000 test-time))
          verification-data (encode-params {
                                            :email "čžýěžě@sfffd.net"
                                            :expires expire
                                            :verified "true"
                                            :time (str test-time)   
                                            })
          signature (hmac-hex "SHA-256" (hash-hex "SHA-256" verification-data) mock-hmac-key)
          payload {:algorithm "SHA-256"
                                     :verified true
                                     :signature signature
                                     :verification-data verification-data
                                     } 
          result (v/verify-server-signature payload mock-hmac-key)
          ]
      (t/is (true? (:verified result)))
      )
    )
  )


(def payload-common {:algorithm "SHA-256"
                                         :number 420
                                         :salt "LoremIpsum"})


(defn- create-b64-payload [challenge]
  (-> (assoc payload-common
         :challenge challenge
         :signature (:signature challenge)
         )
      (clj->json)
      (encode-base64)
  )
  )

(t/deftest test-check-solution-base64 
  (t/testing "Verifies a base64 encoded solution with good values"
   (let [challenge (create-challenge (assoc payload-common
                                      :hmac-key mock-hmac-key
                                      ))
         payload-base64 (create-b64-payload challenge)]
     (t/is (true? (v/check-solution-base64 payload-base64 mock-hmac-key false)))   
     ))
    (t/testing "Challenge created with max-number parameter set"
      (let [challenge (create-challenge (assoc payload-common 
                                               :max-number 9000
                                               :hmac-key mock-hmac-key)) 
            payload-base64 (create-b64-payload challenge)
            ]
        (t/is (true? (v/check-solution-base64 payload-base64 mock-hmac-key false 9000)))
        )
      )
    (t/testing "With expiration"
      (let [;; set expiration time to 90s
            current-time (now)
            challenge (create-challenge (assoc payload-common :hmac-key mock-hmac-key
                                            :current-time current-time 
                                            :ttl 90))
            payload-base64 (create-b64-payload challenge)
            ]
        (println "challenge: " (pr-str challenge))
        (t/is (true? (v/check-solution-base64 payload-base64 mock-hmac-key true
                                              :reference-time current-time
                                              )))
        )
      
      )


  )
