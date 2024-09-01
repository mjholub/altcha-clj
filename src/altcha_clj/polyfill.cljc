(ns altcha-clj.polyfill)

(defn now 
  "Cross-platform function to get the current time
  as a UNIX ms timestamp"
  []
  #?(:clj  (quot (System/currentTimeMillis) 1000)
     :cljs (Math/floor (/ (.now js/Date) 1000))))

(defn parse-int
   "Cross-platform version of parse-long"
  [n]
  #?(:clj (parse-long n)
     :cljs (js/parseInt n 10)
     )
  )
