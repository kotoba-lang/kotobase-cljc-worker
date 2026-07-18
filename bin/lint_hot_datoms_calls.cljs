;; Guardrail against re-introducing the O(N^2) full-scan-without-async-get-fn
;; pattern (kotoba-lang/kotobase-peer#21, kotoba-lang/kotobase-protocols-worker#1):
;; every eng/hot-datoms call in this handler must thread :async-get-fn, or it
;; silently falls back to the with-blocks sync-retry trampoline's O(N^2)
;; block-discovery cost. Run:
;;   nbb bin/lint_hot_datoms_calls.cljs
(ns lint-hot-datoms-calls
  (:require ["fs" :as fs]
            [cljs.reader :as reader]
            [clojure.string :as str]))

(def target-files
  ["src/kotobase/cljc_worker/handler.cljc"])

(def min-hot-datoms-args
  "get-fn chain-cid opts visible? blind-fn decrypt-fn async-get-fn — the
  7-arg arity is the minimum that actually threads async-get-fn through
  (kotobase-peer.core/hot-datoms). Fewer args silently falls back to the
  sync with-blocks trampoline via the omitted-arity default — no error,
  no warning, just slow."
  7)

(defn- balanced-form
  "From `text` starting at the '(' at `start`, return the full balanced
  form as a string. Naive (doesn't understand strings/chars containing
  parens) — adequate for this codebase's call sites; a form the scanner
  can't balance throws rather than silently mis-scanning."
  [text start]
  (loop [i start depth 0]
    (if (>= i (count text))
      (throw (ex-info "unbalanced parens scanning eng/hot-datoms call" {:start start}))
      (let [c (nth text i)
            depth' (cond (= c \() (inc depth) (= c \)) (dec depth) :else depth)]
        (if (and (zero? depth') (= c \)))
          (subs text start (inc i))
          (recur (inc i) depth'))))))

(defn- hot-datoms-arg-count
  "Reader-based, not hand-rolled tokenizing: parse the balanced form as
  real EDN/Clojure data and count its arguments. `#?(:clj ... :cljs ...)`
  reader-conditionals never appear INSIDE a single hot-datoms call in this
  file, so plain cljs.reader suffices."
  [form-str]
  (count (rest (reader/read-string form-str))))

(defn- lint-file [path]
  (let [text (str (fs/readFileSync path "utf8"))]
    (loop [idx 0 problems []]
      (let [found (str/index-of text "(eng/hot-datoms" idx)]
        (if (nil? found)
          problems
          (let [form (balanced-form text found)
                n-args (hot-datoms-arg-count form)
                problems' (if (< n-args min-hot-datoms-args)
                            (conj problems {:file path :n-args n-args
                                            :snippet (subs form 0 (min 80 (count form)))})
                            problems)]
            (recur (+ found (count form)) problems')))))))

(defn -main []
  (let [all-problems (mapcat lint-file target-files)]
    (if (seq all-problems)
      (do
        (println "lint_hot_datoms_calls: FAIL —" (count all-problems) "eng/hot-datoms call(s) missing :async-get-fn")
        (doseq [{:keys [file n-args snippet]} all-problems]
          (println (str "  " file ": " n-args " args (need >= " min-hot-datoms-args ") — " snippet "...")))
        (println "  See kotoba-lang/kotobase-peer#21 / kotoba-lang/kotobase-protocols-worker#1.")
        (set! (.-exitCode js/process) 1))
      (println "lint_hot_datoms_calls: OK — every eng/hot-datoms call threads :async-get-fn"))))

(-main)
