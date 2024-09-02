(ns altcha-clj.polyfill 
  (:require
   [clojure.string :as str]))

(defn now 
  "Cross-platform function to get the current time
  as a UNIX ms timestamp"
  []
  #?(:clj  (quot (System/currentTimeMillis) 1000)
     :cljs (Math/floor (/ (.now js/Date) 1000))))

(defn parse-int
   "Cross-platform version of parse-long.  
   Cleans the input string to only contain digits."
  [n]
(let [cleaned-n (str/replace (str n) #"\D" "")] ; Remove all non-digits
      #?(:clj (Long/parseLong cleaned-n)
         :cljs (js/parseInt cleaned-n 10))
     ))
