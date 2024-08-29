(ns altcha-clj.polyfill)

(defn now 
  "Cross-platform function to get the current time
  as a UNIX ms timestamp"
  []
  #?(:clj  (quot (System/currentTimeMillis) 1000)
     :cljs (Math/floor (/ (.now js/Date) 1000))))
