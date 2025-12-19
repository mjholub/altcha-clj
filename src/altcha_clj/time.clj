(ns altcha-clj.time
  (:import
   [java.lang System]))

(defn now
  "Cross-platform function to get the current time
  as a UNIX ms timestamp"
  []
  (quot (System/currentTimeMillis) 1000))
