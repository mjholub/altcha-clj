(ns altcha-clj.verification-test
  (:require
   #?(:clj [clojure.test :as t]
               :cljs [cljs.test :as t])
   [altcha-clj.core :refer [hmac-hex]]
   [altcha-clj.verify :as v]
   [altcha-clj.encoding :refer [encode-params]]
   [altcha-clj.polyfill :refer [now]]))

(def mock-hmac-key "test key")

(t/deftest verify-server-signature-test 
  (t/testing "Returns a positive verification result
    for good input data that is encoded as a clj map"
    (let [test-time (now)
          expire (str (+ 10000 test-time))
          verification-data (encode-params {
                                            :email "čžýěžě@sfffd.net"
                                            :expire expire
                                            :verified "true"
                                            :time (str test-time)   
                                            })
          signature (hmac-hex "SHA-256" verification-data mock-hmac-key)
          payload (merge {:algorithm "SHA-256"
                                     :verified true
                                     } 
                                         signature
                                        verification-data
                                         )
          result (v/verify-server-signature payload mock-hmac-key)
          ]
      (t/is (true? (:verified result)))
      
      )
    )
  )
