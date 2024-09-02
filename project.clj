(defproject me.mjholub/altcha-clj "1.2.3"
  :description "A Clojure/script library designed for working with Altcha challenges."
  :url "https://github.com/mjholub/altcha-clj"
  :license {:name "LGPL-3.0-or-later"
            :url "https://www.gnu.org/licenses/lgpl-3.0.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [cheshire "5.13.0"]
                 ]
  :repl-options {:init-ns altcha-clj.core})
