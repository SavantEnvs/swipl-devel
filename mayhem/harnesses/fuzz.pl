/*  Prolog drivers for the libFuzzer harness mayhem/harnesses/fuzz_swipl.c.

    Each fuzz_<target>(+In) gets a read-only input stream over the fuzz input and must close it.
    Drivers only call side-effect-free builtins from allow-lists: no file system, shell, network,
    flags or global state that outlives the call. What is kept across inputs on purpose: the atom
    table (garbage collected by AGC) and the max_integer_size flag set once below (read-only after).
*/

:- set_prolog_flag(max_integer_size, 100000).   % bound bigint growth (bytes), set once
:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(date)).
:- use_module(library(sgml)).
:- use_module(library(uri)).
:- use_module(library(json)).
:- use_module(library(redis)).

%!  run(:Goal, +In)
%   Run call(Goal, In) once, catching everything, and always close In.
run(Goal, In) :-
    catch(setup_call_cleanup(true, once(call(Goal, In)),
                             catch(close(In, [force(true)]), _, true)),
          _, true),
    !.
run(_, In) :-
    catch(close(In, [force(true)]), _, true).

%   Read up to Max terms from In, calling Action on each; syntax errors are skipped.
for_terms(In, Max, Action) :-
    between(1, Max, _),
    catch(read_term(In, T, []), E, (T = '$error'(E))),
    (   T == end_of_file
    ->  !
    ;   T = '$error'(_), at_end_of_stream(In)
    ->  !
    ;   T = '$error'(_)
    ->  fail
    ;   catch(ignore(call(Action, T)), _, true),
        fail
    ).
for_terms(_, _, _).

to_string(T, S) :-
    with_output_to(string(S), print(T)).

%%%%%%%%%%%%%%%% read: the term reader (pl-read.c) on a UTF-8 source file %%%%%%%%%%%%%%%%

%   The bytes are written to a private temporary file ($TMPDIR, deleted afterwards) and read back
%   through a UTF-8 file stream, the way consult/1 reads source. (Reading invalid UTF-8 from an
%   in-memory string stream trips an assertion in Speekcode() on the first truncated multibyte
%   sequence, which would mask every other reader path.)
fuzz_read(In) :- run(read_file, In).

read_file(In) :-
    with_tmp_copy(In, File,
                  setup_call_cleanup(open(File, read, S, [encoding(utf8)]),
                                     read_terms(S),
                                     close(S))).

%   with_tmp_copy(+In, -File, :Goal): copy the input stream to a fresh temporary file, run Goal,
%   delete the file.
with_tmp_copy(In, File, Goal) :-
    tmp_file_stream(binary, File, Out),
    call_cleanup(( call_cleanup(copy_stream_data(In, Out), close(Out)),
                   ignore(Goal) ),
                 catch(delete_file(File), _, true)).

read_terms(In) :-
    between(1, 200, _),
    catch(read_term(In, T, [ variable_names(Vs), subterm_positions(P), comments(C),
                             term_position(_), syntax_errors(error) ]),
          _, (T = '$error')),
    (   T == end_of_file
    ->  !
    ;   T == '$error', at_end_of_stream(In)
    ->  !
    ;   T == '$error'
    ->  fail
    ;   catch(( with_output_to(string(_), ( write_term(T, [quoted(true), variable_names(Vs)]),
                                            write_canonical(T), print(P-C) )),
                term_to_atom(T, A), atom_length(A, _) ), _, true),
        fail
    ).
read_terms(_).

%%%%%%%%%%%%%%%% trie: op script over one trie (pl-trie.c) %%%%%%%%%%%%%%%%

fuzz_trie(In) :- run(trie_script, In).

trie_script(In) :-
    trie_new(Trie),
    call_cleanup(( for_terms(In, 500, trie_op(Trie)),
                   catch(forall(trie_gen(Trie, K, V), to_string(K-V, _)), _, true) ),
                 trie_destroy(Trie)).

trie_op(T, i(K))    :- trie_insert(T, K).
trie_op(T, i(K,V))  :- trie_insert(T, K, V).
trie_op(T, n(K,V))  :- trie_insert(T, K, V, Node), trie_term(Node, X), to_string(X, _).
trie_op(T, u(K,V))  :- trie_update(T, K, V).
trie_op(T, d(K))    :- trie_delete(T, K, _).
trie_op(T, l(K))    :- trie_lookup(T, K, V), to_string(V, _).
trie_op(T, g(K))    :- forall(trie_gen(T, K, V), to_string(K-V, _)).
trie_op(T, g)       :- forall(trie_gen(T, K), to_string(K, _)).
trie_op(T, c(K))    :- forall(trie_gen_compiled(T, K, V), to_string(K-V, _)).
trie_op(T, p)       :- forall(trie_property(T, P), to_string(P, _)).

%%%%%%%%%%%%%%%% compile: assert + run clauses (pl-comp.c, VM) %%%%%%%%%%%%%%%%

%   Clauses are rewritten so they can only call allow-listed side-effect-free builtins and each
%   other: every other goal is renamed into the temporary module (fz_<name>), variable goals
%   become fail. Running them is bounded by an inference limit: an endless loop in fuzzed
%   Prolog is the program's semantics, not an interpreter bug.

fuzz_compile(In) :- run(compile_script, In).

compile_script(In) :-
    in_temporary_module(M, set_prolog_flag(M:unknown, fail), compile_in(M, In)).

compile_in(M, In) :-
    for_terms(In, 100, add_clause(M)),
    findall(N/A, ( current_predicate(M:N/A), \+ predicate_property(M:_, imported_from(_)) ), Ps0),
    sort(Ps0, Ps),
    forall(member(N/A, Ps),
           ( functor(H, N, A),
             catch(forall(clause(M:H, B), with_output_to(string(_), portray_clause((H:-B)))), _, true),
             catch(call_with_inference_limit(forall(M:H, true), 20000, _), _, true) )).

add_clause(_, (:- _)) :- !.
add_clause(M, (H --> B)) :- !,
    dcg_translate_rule((H --> B), C),
    add_clause(M, C).
add_clause(M, (H :- B)) :- !,
    callable(H), rename_head(H, H1), safe_body(B, B1),
    assertz(M:(H1 :- B1)).
add_clause(M, H) :-
    callable(H), rename_head(H, H1),
    assertz(M:H1).

rename_head(H, H1) :-
    compound_name_arguments(H, N, As), atom(N),
    atom_concat('fz_', N, N1),
    compound_name_arguments(H1, N1, As).
rename_head(H, H1) :-
    atom(H), atom_concat('fz_', H, H1).

safe_body(G, fail) :- var(G), !.
safe_body((A,B), (A1,B1)) :- !, safe_body(A, A1), safe_body(B, B1).
safe_body((A;B), (A1;B1)) :- !, safe_body(A, A1), safe_body(B, B1).
safe_body((A->B), (A1->B1)) :- !, safe_body(A, A1), safe_body(B, B1).
safe_body((A*->B), (A1*->B1)) :- !, safe_body(A, A1), safe_body(B, B1).
safe_body(\+ A, \+ A1) :- !, safe_body(A, A1).
safe_body(findall(T,G,L), findall(T,G1,L)) :- !, safe_body(G, G1).
safe_body(forall(C,A), forall(C1,A1)) :- !, safe_body(C, C1), safe_body(A, A1).
safe_body(G, G) :- callable(G), functor(G, N, A), safe_builtin(N, A), !.
safe_body(G, G1) :- callable(G), rename_head(G, G1), !.
safe_body(_, fail).

safe_builtin(N, A) :- memberchk(N/A,
    [ true/0, fail/0, false/0, !/0, (=)/2, (\=)/2, (==)/2, (\==)/2, (@<)/2, (@>)/2, (@=<)/2,
      (@>=)/2, compare/3, var/1, nonvar/1, atom/1, number/1, integer/1, float/1, atomic/1,
      compound/1, callable/1, is_list/1, string/1, ground/1, is_dict/1, rational/1,
      (is)/2, (<)/2, (>)/2, (=<)/2, (>=)/2, (=:=)/2, (=\=)/2, succ/2, plus/3,
      functor/3, arg/3, (=..)/2, copy_term/2, setarg/3, nb_setarg/3, term_variables/2,
      atom_codes/2, atom_length/2, atom_chars/2, char_code/2, number_codes/2, sub_atom/5,
      length/2, msort/2, sort/2, sort/4, keysort/2, between/3, unify_with_occurs_check/2,
      cyclic_term/1, acyclic_term/1, tab/0, (?=)/2, subsumes_term/2, term_hash/2,
      get_dict/3, put_dict/4, dict_pairs/3
    ]).

%%%%%%%%%%%%%%%% format: format/2,3 directives (pl-fmt.c) %%%%%%%%%%%%%%%%

%   Input terms: Format-Args or Enc:(Format-Args); output goes to a string and to a null stream
%   with the chosen encoding. ~@ (call a goal) is rejected: it would run arbitrary code.

fuzz_format(In) :- run(format_script, In).

format_script(In) :- for_terms(In, 100, format_one).

format_one(E:(F-A)) :- !, format_enc(E, F, A).
format_one(F-A) :- format_enc(utf8, F, A).

format_enc(E, F, A0) :-
    memberchk(E, [utf8, iso_latin_1, ascii, utf16be, utf16le, octet, text, wchar_t, unicode_be, unicode_le]),
    ground(F-A0),
    text_to_string(F, FS),
    \+ sub_string(FS, _, _, _, "@"),           % ~@ calls a goal
    \+ sub_string(FS, _, _, _, "*"),           % ~*c: unbounded column/repeat counts from args
    \+ ( sub_atom(FS, _, 5, _, D5), atom_number(D5, _) ),  % numeric arguments of 5+ digits: huge output
    ( is_list(A0) -> A = A0 ; A = [A0] ),
    \+ ( sub_term(X, A), compound(X), functor(X, Opt, _),   % ~W options that call goals
          memberchk(Opt, [portray_goal, portray, blobs]) ),
    with_output_to(string(S), format(FS, A)), string_length(S, _),
    setup_call_cleanup(open_null_stream(Out),
                       ( set_stream(Out, encoding(E)), format(Out, FS, A) ),
                       close(Out)).

%%%%%%%%%%%%%%%% text: text/atom/string builtins + write_term (pl-text.c, pl-write.c) %%%%%%%%%%%%%%%%

%   Input terms: Goal, where Goal is an allow-listed text predicate; or closed(X, Goal) which
%   binds X to a released stream blob first; or w(Term, Options) for write_term/3 with allow-listed
%   options, written to null streams in several encodings.

fuzz_text(In) :- run(text_script, In).

text_script(In) :- for_terms(In, 100, text_one).

text_one(closed(X, G)) :- !,
    open_null_stream(X), close(X),
    text_one(G).
text_one(w(T, Opts0)) :- !,
    is_list(Opts0),
    include(safe_write_option, Opts0, Opts),
    forall(member(E, [utf8, iso_latin_1, ascii, utf16le]),
           catch(setup_call_cleanup(open_null_stream(Out),
                                    ( set_stream(Out, encoding(E)), write_term(Out, T, Opts) ),
                                    close(Out)), _, true)),
    with_output_to(string(S), write_term(T, Opts)), string_length(S, _).
text_one(G) :-
    callable(G), functor(G, N, A), text_builtin(N, A),
    call_with_inference_limit(forall(G, true), 100000, _).

safe_write_option(O) :-
    compound(O), functor(O, N, 1),
    memberchk(N, [quoted, ignore_ops, dotlists, brace_terms, max_depth, numbervars,
                  character_escapes, character_escapes_unicode, spacing, cycles, no_lists,
                  fullstop, nl, quote_non_ascii, back_quotes, variable_names, partial]).

text_builtin(N, A) :- memberchk(N/A,
    [ atom_codes/2, atom_chars/2, char_code/2, atom_length/2, string_length/2, atom_number/2,
      number_codes/2, number_chars/2, number_string/2, atom_string/2, string_chars/2,
      string_codes/2, string_code/3, string_to_atom/2, sub_atom/5, sub_string/5,
      split_string/4, string_concat/3, atom_concat/3, atomic_list_concat/2,
      atomic_list_concat/3, upcase_atom/2, downcase_atom/2, string_lower/2, string_upper/2,
      term_to_atom/2, term_string/2, text_concat/3, text_to_string/2, char_type/2,
      code_type/2, normalize_space/2, string_bytes/3, read_term_from_atom/3, atom_to_term/3,
      sub_atom_icasechk/3, collation_key/2, atomic_concat/3, string/1, text_length/2,
      compare/3, (==)/2, (@<)/2, msort/2, sort/4, blob/2, term_hash/2, variant_sha1/2,
      variant_hash/2, copy_term/2
    ]).

%%%%%%%%%%%%%%%% arith: is/2 and comparison (pl-arith.c, GMP) %%%%%%%%%%%%%%%%

fuzz_arith(In) :- run(arith_script, In).

arith_script(In) :- for_terms(In, 100, arith_one).

arith_one(T) :-
    \+ ( sub_term(S, T), callable(S), functor(S, N, _),      % no clock or random-state functions
          memberchk(N, [random, random_float, cputime, realtime]) ),
    (   compound(T), T =.. [Op, A, B], memberchk(Op, [<, >, =<, >=, =:=, =\=])
    ->  ignore(call(Op, A, B))
    ;   X is T,
        format(string(_), "~w ~q ~a", [X, X, '']),
        ( number(X) -> format(string(_), "~e ~4f ~g", [X, X, X]) ; true )
    ).

%%%%%%%%%%%%%%%% fast_read: binary term deserializer (pl-rec.c) %%%%%%%%%%%%%%%%

fuzz_fast_read(In) :- run(fast_read_script, In).

fast_read_script(In) :-
    between(1, 100, _),
    catch(fast_read(In, T), _, T = end_of_file),
    (   T == end_of_file
    ->  !
    ;   catch(( copy_term(T, T2), to_string(T2, _), term_hash(T, _) ), _, true),
        fail
    ).
fast_read_script(_).

%%%%%%%%%%%%%%%% wildcard: glob pattern compiler/matcher (pl-glob.c) %%%%%%%%%%%%%%%%

%   Input: Pattern NL Subject.
fuzz_wildcard(In) :- run(wildcard_script, In).

wildcard_script(In) :-
    read_string(In, _, Str),
    (   sub_string(Str, B, _, Af, "\n")
    ->  sub_string(Str, 0, B, _, P), sub_string(Str, _, Af, 0, S)
    ;   P = Str, S = ""
    ),
    !,
    ignore(catch(wildcard_match(P, S), _, true)),
    ignore(catch(wildcard_match(P, S, [case_sensitive(false)]), _, true)).

%%%%%%%%%%%%%%%% format_time: strftime-like formatter + date conversion (pl-tai.c) %%%%%%%%%%%%%%%%

%   Input terms: Format-Stamp (Stamp a number or date/9 term), p(Text) for parse_time/3,
%   s(Stamp) for stamp_date_time/3 + date_time_stamp/2.
fuzz_format_time(In) :- run(time_script, In).

time_script(In) :- for_terms(In, 100, time_one).

time_one(F-Stamp) :-
    format_time(string(_), F, Stamp),
    format_time(string(_), F, Stamp, posix).
time_one(p(Text)) :-
    forall(member(Fmt, [_, iso_8601, rfc_1123]), ignore(catch(parse_time(Text, Fmt, _), _, true))).
time_one(s(Stamp)) :-
    stamp_date_time(Stamp, D, 'UTC'), date_time_stamp(D, S2),
    stamp_date_time(S2, D2, 0), date_time_stamp(D2, _).
time_one(d(D)) :-
    date_time_stamp(D, S), stamp_date_time(S, _, 'UTC').

%%%%%%%%%%%%%%%% sgml: XML/SGML/HTML parser (packages/sgml parser.c) %%%%%%%%%%%%%%%%

%   The first byte picks the dialect; the rest is the document.
fuzz_sgml(In) :- run(sgml_script, In).

sgml_script(In) :-
    get_char(In, C), C \== end_of_file,
    char_code(C, X), I is X mod 5,
    nth0(I, [xml, xmlns, sgml, html5, html], D),
    load_structure(stream(In), DOM, [dialect(D), max_errors(-1), syntax_errors(quiet),
                                     space(sgml)]),
    with_output_to(string(_), print(DOM)).

%%%%%%%%%%%%%%%% json: JSON reader (packages/json) %%%%%%%%%%%%%%%%

fuzz_json(In) :- run(json_script, In).

json_script(In) :-
    json_read_dict(In, D, [value_string_as(string)]),
    setup_call_cleanup(open_null_stream(Out), json_write_dict(Out, D, []), close(Out)),
    atom_json_dict(A, D, []), atom_json_term(A, T, []), atom_length(A, _), ground(T).

%%%%%%%%%%%%%%%% uri: URI parsing, normalisation, resolution (packages/clib uri.c) %%%%%%%%%%%%%%%%

%   Input: URI NL Base.
fuzz_uri(In) :- run(uri_script, In).

uri_script(In) :-
    read_string(In, _, Str),
    (   sub_string(Str, B, _, Af, "\n")
    ->  sub_string(Str, 0, B, _, U), sub_string(Str, _, Af, 0, Base)
    ;   U = Str, Base = "http://a/b/c/d;p?q"
    ),
    !,
    forall(member(G, [ uri_components(U, _), uri_normalized(U, _), uri_iri(U, _),
                       uri_iri(_, U), uri_normalized_iri(U, _), uri_resolve(U, Base, _),
                       uri_normalized(U, Base, _), uri_is_global(U),
                       uri_query_components(U, _), uri_encoded(query_value, _, U),
                       uri_encoded(path, U, _), uri_authority_components(U, _),
                       uri_file_name(U, _) ]),
           ignore(catch(G, _, true))),
    ignore(catch(( uri_components(U, C), uri_components(U2, C), atom_length(U2, _) ), _, true)).

%%%%%%%%%%%%%%%% redis: RESP2/RESP3 reply parser (packages/redis redis4pl.c) %%%%%%%%%%%%%%%%

%   The input is the byte stream a Redis server sends back. Replies are read with the client's own
%   reader, redis_read_msg/5 (what redis/2,3 and redis_read_stream/3 call), until end of stream or
%   the first protocol error (where the real client drops or resyncs the connection). Each reply is
%   decoded with one of the client's `Reply as Type` conversions, chosen by its position in the
%   stream. No connection object is involved, so nothing outlives the input.

fuzz_redis(In) :- run(redis_script, In).

redis_script(In) :-
    between(0, 199, I),
    (   at_end_of_stream(In)
    ->  !
    ;   redis_as(I, MsgIn),
        catch(redis:redis_read_msg(In, MsgIn, Out, Err, Push), _, fail)
    ->  catch(to_string(Out-Err-Push, _), _, true),
        fail
    ;   !
    ).
redis_script(_).

redis_as(I, Msg) :-
    Types = [ auto, string, bytes, codes, chars, atom, integer, tagged_integer, float, rational,
              number, auto(string, number), auto(atom, integer), pairs(atom, auto), pairs(string,
              string), dict_key, dict(auto), dict(dict_key, auto), prolog ],
    length(Types, N),
    K is I mod (N+1),
    (   K =:= N
    ->  true                                   % no conversion: the default reply decoding
    ;   nth0(K, Types, T), Msg = (_ as T)
    ).
