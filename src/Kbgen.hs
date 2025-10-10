-- |
--
-- * The [knowledge base](https://en.wikipedia.org/wiki/Knowledge_representation_and_reasoning) ( kb )
--   aims to be a data structure able to:
--
--     * represent /multiple/ facts about the source code repo
--     * from /various/ programming languages
--     * each fact can be translated to a [Prolog](https://en.wikipedia.org/wiki/Prolog) fact
--     * facts can be combined to create [predicates](https://en.wikipedia.org/wiki/Predicate_%28logic%29)
--     * [predicates](https://en.wikipedia.org/wiki/Predicate_%28logic%29) can be combined to formulate /security queries/
--
-- * Facts describe relations between:
--
--     * code locations
--     * const strings
--     * const integers
--
-- * Code locations are capable of representing /all/ program entities
--
--     * classes
--     * methods
--     * lambdas
--     * annotations
--     * arguments
--     * parameters
--     * etc.
--
-- * Facts can be /combined/:
--
--     * [conjunction](https://en.wikipedia.org/wiki/Logical_conjunction)
--     * [disjunction](https://en.wikipedia.org/wiki/Logical_disjunction)
--     * [negation](https://en.wikipedia.org/wiki/Negation)
--
-- * [Prolog](https://en.wikipedia.org/wiki/Prolog) queries are /easy/ to write:
--
--     * you /don't/ have to be a Prolog expert
--     * copy-paste the basic facts to /any/ [LLM](https://en.wikipedia.org/wiki/Large_language_model)
--     * explain in plain English your query's purpose
--     * et voilà !
--
-- * Its main purpose is to serve as the:
--
--     * penultimate step for /static code analysis/ 
--     * part of the [dhscanner](https://github.com/OrenGitHub/dhscanner.vps) framework
--
--         * [SAST](https://en.wikipedia.org/wiki/Static_application_security_testing) for security scans 🔒
--         * [PII](https://en.wikipedia.org/wiki/Personal_data) leaks detection 🪪
--

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE OverloadedStrings #-}

module Kbgen (
    KeywordArgForCall(..),
    ParamResolvedType(..),
    ClassName(..),
    ParamName(..),
    ConstString(..),
    ArgForCall(..),
    MethodOfClass(..),
    ClassResolvedSuper(..),
    ClassNamedSuper(..),
    ArgiForCall(..),
    ConstBoolTrue(..),
    ClassAnnotation,
    CallableAnnotation,
    ParamiOfCallable(..),
    prologify,
    Arg(..),
    Call(..),
    Class(..),
    Param(..),
    Method(..),
    Callable(..),
    Keyword(..),
    Resolved(..),
    ArgIndex(..),
    ParamIndex(..),
    ResolvedType(..),
    CallResolved(..),
    ResolvedSuper(..),
    ConstStr(..),
    Fact(..)
)

where

import Data.Aeson
import Text.Printf
import GHC.Generics

-- project imports
import Location
import qualified Token
import Fqn hiding ( content )

-- |
--
-- __Name__
--
-- This is how the fact will look inside the Prolog file
--
-- @
-- kb_keyword_arg_for_call( Keyword, Arg, Call ).
-- @
--
-- __When should I use this fact__ ( motivation: [CVE-2024-52803](https://nvd.nist.gov/vuln/detail/CVE-2024-52803) )
--
-- Code snippet ( Python ):
--
-- @
-- Popen(f'llamafactory-cli train {save_cmd(args)}', env=env, shell=True)
-- @
--
-- See complete source example: [here](https://github.com/hiyouga/LLaMA-Factory/commit/b3aa80d54a67da45e9e237e349486fb9c162b2ac)
--
-- __Writing a predicate with this fact and others__ ( motivation: [CVE-2024-52803](https://nvd.nist.gov/vuln/detail/CVE-2024-52803) )
--
-- @
-- subprocess_Popen_called_with_shell_eq_True( Call ) :-
--     kb_keyword_arg_for_call( \'shell\', TrueValue, Call ),
--     kb_call_resolved( Call, \'subprocess.Popen\' ),
--     kb_const_bool_true( TrueValue ).
-- @
--
-- Other facts combined in this example predicate:
--
--     * 'CallResolved'
--     * 'ConstBoolTrue'
--
data KeywordArgForCall = KeywordArgForCall
    Keyword -- ^
    Arg -- ^
    Call -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- __Name__
--
-- This is how the fact will look inside the Prolog file
--
-- @
-- kb_param_has_resolved_type( Param, ResolvedType ).
-- @
--
-- __When should I use this fact__ ( motivation: [CVE-2024-49380](https://nvd.nist.gov/vuln/detail/CVE-2024-49380) )
--
-- Code snippet ( Golang ):
--
-- @
-- func postLocal(w http.ResponseWriter, r *http.Request) { ... }
-- @
--
-- See complete source example: [here](https://github.com/plentico/plenti/blob/01825e0dcd3505fac57adc2edf29f772d585c008/cmd/serve.go#L205)
--
-- __Writing a predicate with this fact and others__ ( motivation: [CVE-2024-49380](https://nvd.nist.gov/vuln/detail/CVE-2024-49380) )
--
-- @
-- looks_like_user_input( RequestParam ) :-
--     kb_param_has_resolved_type( RequestParam, \'net/http.Request\' ),
--     kb_param_has_resolved_type( ResponseParam, \'net/http.ResponseWriter\' ),
--     kb_param_i_of_callable( ResponseParam, 0, Handler ),
--     kb_param_i_of_callable( RequestParam, 1, Handler ).
-- @
--
-- Other facts combined in this predicate:
--
--     * 'ParamiOfCallable'
--
data ParamResolvedType = ParamResolvedType
    Param -- ^
    ResolvedType -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- __Name__
--
-- This is how the fact will look inside the Prolog file
--
-- @
-- kb_class_name( Class, Name ).
-- @
--
-- __When should I use this fact__ ( motivation: [CVE-2024-53995](https://nvd.nist.gov/vuln/detail/CVE-2024-53995) )
--
-- @
-- # authentication.py
-- class LoginHandler(BaseHandler): ...
--
-- # index.py
-- from tornado.web import RequestHandler
-- class BaseHandler(RequestHandler): ...
-- @
--
-- See complete source example [here](https://github.com/SickChill/sickchill/blob/846adafdfab579281353ea08a27bbb813f9a9872/sickchill/views/authentication.py#L10),
-- [here](https://github.com/SickChill/sickchill/blob/846adafdfab579281353ea08a27bbb813f9a9872/sickchill/views/index.py#L35)
-- and [here](https://github.com/SickChill/sickchill/blob/846adafdfab579281353ea08a27bbb813f9a9872/sickchill/views/index.py#L15)
--
-- __Writing a predicate with this fact and others__ ( motivation: [CVE-2024-53995](https://nvd.nist.gov/vuln/detail/CVE-2024-53995) )
--
-- @
-- skip_level_subclass_of( Subclass, \'tornado.web.RequestHandler\' ) :-
--     kb_class_name( Class, ClassType ),
--     kb_class_named_super( Subclass, ClassType ),
--     kb_class_resolved_super( Class, \'tornado.web.RequestHandler\' ).
-- @
--
-- Other facts combined in this predicate:
--
--     * 'ClassNamedSuper'
--     * 'ClassResolvedSuper'
--
data ClassName = ClassName
    Class -- ^
    Token.ClassName -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- __Description:__
--
-- Input parameter of some callable ( method, function, lambda ) has the specified name
--
-- __Prolog signature:__
--
-- @
-- kb_param_has_name( Param, Name ).
-- @
--
-- __Code Example ( Javascript ):__
--
-- Motivated by [GHSL-2023-203](https://github.com/advplyr/audiobookshelf/security/advisories/GHSA-mgj7-rfx8-vhpr#event-116560)
-- ( [source code](https://github.com/advplyr/audiobookshelf/blob/d7b2476473ef1934eedec41425837cddf2d4b13e/server/controllers/AuthorController.js#L66)
-- and see also [here](https://github.com/advplyr/audiobookshelf/blob/d7b2476473ef1934eedec41425837cddf2d4b13e/server/controllers/AuthorController.js#L74)
-- and [here](https://github.com/advplyr/audiobookshelf/blob/d7b2476473ef1934eedec41425837cddf2d4b13e/server/routers/ApiRouter.js#L201) )
--
-- @
-- // ApiRouter.js
-- const express = require(\'express\')
--
-- class ApiRouter {
--   constructor(Server) { this.router = express() }
--   init() { this.router.patch(\'\/authors\/:id', ... , AuthorController.update.bind(this)) }
--
-- // AuthorController.js
-- class AuthorController { async update(req, res) { ... } }
-- @
--
-- __Writing new predicates:__
--
-- Facts combined in this predicate:
--
--     * 'ParamName'
--     * 'ParamiOfCallable'
--
-- @
-- http_request_param_of_method( Param, Method ) :-
--     kb_param_name( Param, \'req\' ),
--     kb_param_name( SecondParam, \'res\' ),
--     kb_param_i_of_callable( Param, 0, Method ),
--     kb_param_i_of_callable( SecondParam, 1, Method ).
-- @
--
-- Facts combined in this predicate:
--
--     * 'ArgiForCall'
--     * 'ClassName'
--     * 'MethodName'
--
-- @
-- request_handler( Method ) :-
--     kb_resolved_call( Call, \'express.patch\' ),
--     kb_arg_i_for_call( RequestHandler, 2, Call ),
--     kb_resolved_part_i_call( RequestHandler, 0, ClassName ),
--     kb_resolved_part_i_call( RequestHandler, 1, MethodName ),
--     kb_method_of_class( Method, Class ),
--     kb_method_name( Method, MethodName ),
--     kb_class_name( Class, ClassName ).
-- @
--
--
data ParamName = ParamName
    Param -- ^
    Token.ParamName -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- Usage:
--
-- @
-- kb_subclass_of( Class, SuperName ).
-- @
--
-- * usually used with 'ClassResolvedSuper'
-- * for bounded inheritance of third party classes
--
-- ==== __Example:__
--
-- @
-- kb_class_name(Class,ClassName).
-- @
--
data ClassNamedSuper = ClassNamedSuper
    Class -- ^
    Token.SuperName -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- * usually used with 'ClassNamedSuper'
-- * for bounded inheritance of third party classes
--
-- ==== __Example:__
--
-- @
-- kb_class_super_name(Class,SuperFqsdfsdfsdfn).
-- @
--
data ClassResolvedSuper = ClassResolvedSuper
    Class -- ^
    ResolvedSuper -- ^ ( 1 fact per super class )
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
-- capture inheritance from third party classes
data ClassAnnotation = ClassAnnotation
    Class -- ^
    Annotation -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

data CallableAnnotation = CallableAnnotation
    Callable -- ^
    Annotation -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
-- capture usage of inherited third party methods
data MethodOfClass = MethodOfClass
    Method -- ^
    Class -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- Usage:
--
-- @
-- ArgiForCall( Arg, Index, Call ).
-- @
--
-- ==== __Tip 💡__
--
-- sometimes the index is irrelevant, see 'ArgForCall'
--
data ArgiForCall = ArgiForCall
    Arg -- ^
    ArgIndex -- ^
    Call -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- Usage:
--
-- @
-- arg_for_call( Arg, Call ).
-- @
--
-- ==== __Tip 💡__
--
-- sometimes the exact index is irrelevant, see 'ArgForCall'
--
data ArgForCall = ArgForCall
    Arg -- ^
    Call -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- Usage:
--
-- @
-- ParamiOfCallable( Param, Index, Callable ).
-- @
--
-- ==== __Tip 💡__
--
-- sometimes the exact index is irrelevant, see 'Arg_for_Call'
--
data ParamiOfCallable = ParamiOfCallable
    Param -- ^
    ParamIndex -- ^ 0-based
    Callable -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

-- |
--
-- Usage:
--
-- @
-- kb_const_str( Param, Index, Callable ).
-- @
--
-- ==== __Tip 💡__
--
-- sometimes the exact index is irrelevant, see 'Arg_for_Call'
--
data ConstString = ConstString
    ConstStr -- ^
    Token.ConstStr -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

data Arg = Arg Location deriving ( Show, Generic, ToJSON, FromJSON )
data Call = Call Location deriving ( Show, Generic, ToJSON, FromJSON )
data Param = Param Location deriving ( Show, Generic, ToJSON, FromJSON )
data Class = Class Location deriving ( Show, Generic, ToJSON, FromJSON )

data CallResolved = CallResolved
    Call -- ^
    Resolved -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

data Method = Method Location deriving ( Show, Generic, ToJSON, FromJSON )
data Callable = Callable Location deriving ( Show, Generic, ToJSON, FromJSON )
data ConstStr = ConstStr Location deriving ( Show, Generic, ToJSON, FromJSON )
data Annotation = Annotation Location deriving ( Show, Generic, ToJSON, FromJSON )
data ConstBoolTrue = ConstBoolTrue Location deriving ( Show, Generic, ToJSON, FromJSON )

data Keyword = Keyword String deriving ( Show, Generic, ToJSON, FromJSON )
data Resolved = Resolved Fqn deriving ( Show, Generic, ToJSON, FromJSON )
data ArgIndex = ArgIndex Word deriving ( Show, Generic, ToJSON, FromJSON )
data ParamIndex = ParamIndex Word deriving ( Show, Generic, ToJSON, FromJSON )
data ConstStrValue = ConstStrValue String deriving ( Show, Generic, ToJSON, FromJSON )

-- |
data ResolvedType = ResolvedType
    Fqn -- ^
    deriving ( Show, Generic, ToJSON, FromJSON )

data ResolvedSuper = ResolvedSuper Fqn deriving ( Show, Generic, ToJSON, FromJSON )

-- |
-- * each fact is derived from a /single/ bitcode 'Bitcode.Instruction'
--
-- * often, a single bitcode instruction will yield /more/ than one fact
--
data Fact
   = ParamNameCtor ParamName
   | ClassNameCtor ClassName
   | ArgForCallCtor ArgForCall
   | ArgiForCallCtor ArgiForCall
   | ConstStringCtor ConstString
   | CallResolvedCtor CallResolved
   | ConstBoolTrueCtor ConstBoolTrue
   | MethodOfClassCtor MethodOfClass
   | ClassNamedSuperCtor ClassNamedSuper
   | ClassAnnotationCtor ClassAnnotation
   | ParamiOfCallableCtor ParamiOfCallable
   | KeywordArgForCallCtor KeywordArgForCall
   | ParamResolvedTypeCtor ParamResolvedType
   | ClassResolvedSuperCtor ClassResolvedSuper
   | CallableAnnotationCtor CallableAnnotation
   deriving ( Show, Generic, ToJSON, FromJSON )

-- |
-- Translate a code fact into a prolog fact
--
-- 'ParamName'
--
-- @
-- kb_param_has_name( Param, Name ).
-- @
--
prologify :: Fact -> String
prologify (ParamNameCtor content) = prologify_ParamName content
prologify (ClassNameCtor content) = prologify_ClassName content
prologify (ArgForCallCtor content) = prologifyArgForCall content
prologify (ArgiForCallCtor content) = prologifyArgiForCall content
prologify (ConstStringCtor content) = prologify_ConstString content
prologify (CallResolvedCtor content) = prologify_CallResolved content
prologify (ConstBoolTrueCtor content) = prologify_ConstBoolTrue content
prologify (MethodOfClassCtor content) = prologify_MethodOfClass content
prologify (ClassNamedSuperCtor content) = prologifyClassNamedSuper content
prologify (ClassAnnotationCtor content) = prologify_ClassAnnotation content
prologify (ParamiOfCallableCtor content) = prologify_ParamiOfCallable content
prologify (ParamResolvedTypeCtor content) = prologify_ParamResolvedType content
prologify (KeywordArgForCallCtor content) = prologify_KeywordArgForCall content
prologify (ClassResolvedSuperCtor content) = prologifyClassResolvedSuper content
prologify (CallableAnnotationCtor content) = prologify_CallableAnnotation content

prologify_ParamResolvedType' :: Location -> String -> String
prologify_ParamResolvedType' l fqn = printf "kb_param_has_type( %s, \'%s\' )." (locationify l) fqn

prologify_ParamResolvedType :: ParamResolvedType -> String
prologify_ParamResolvedType (ParamResolvedType (Param loc) (ResolvedType (Fqn content))) = prologify_ParamResolvedType' loc content

prologify_ParamName' :: Location -> String -> String
prologify_ParamName' l name = printf "kb_param_has_name( %s, \'%s\' )." (locationify l) name

prologify_ParamName :: ParamName -> String
prologify_ParamName (ParamName (Param loc) (Token.ParamName (Token.Named name _))) = prologify_ParamName' loc name

prologify_ClassName' :: Location -> String -> String
prologify_ClassName' l name = printf "kb_class_name( %s, \'%s\' )." (locationify l) name

prologify_ClassName :: ClassName -> String
prologify_ClassName (ClassName (Class loc) (Token.ClassName (Token.Named name _))) = prologify_ClassName' loc name

prologify_ConstString' :: Location -> String -> String
prologify_ConstString' l value = printf "kb_const_string( %s, \'%s\' )." (locationify l) value

prologify_ConstString :: ConstString -> String
prologify_ConstString (ConstString (ConstStr loc) (Token.ConstStr value _)) = prologify_ConstString' loc value

prologify_CallResolved' :: Location -> String -> String
prologify_CallResolved' call resolved = printf "kb_call_resolved( %s, \'%s\' )." (locationify call) resolved

prologify_CallResolved :: CallResolved -> String
prologify_CallResolved (CallResolved (Call call) (Resolved (Fqn content))) = prologify_CallResolved' call content

prologify_ConstBoolTrue' :: Location -> String
prologify_ConstBoolTrue' trueValue = printf "kb_class_name( %s, \'%s\' )." (locationify trueValue)

prologify_ConstBoolTrue :: ConstBoolTrue -> String
prologify_ConstBoolTrue (ConstBoolTrue trueValue) = prologify_ConstBoolTrue' trueValue

prologifyArgForCall' :: Location -> Location -> String
prologifyArgForCall' a c = printf "kb_arg_for_call( %s, %s )." (locationify a) (locationify c)

prologifyArgForCall :: ArgForCall -> String
prologifyArgForCall (ArgForCall (Arg a) (Call c)) = prologifyArgForCall' a c

prologify_MethodOfClass' :: Location -> Location -> String
prologify_MethodOfClass' m c = printf "kb_method_of_class( %s, %s )." (locationify m) (locationify c)

prologify_MethodOfClass :: MethodOfClass -> String
prologify_MethodOfClass (MethodOfClass (Method m) (Class c)) = prologify_MethodOfClass' m c

prologifyClassResolvedSuper' :: Location -> String -> String
prologifyClassResolvedSuper' l s = printf "kb_class_has_resolved_super( %s, \'%s\' )." (locationify l) s
 
prologifyClassResolvedSuper :: ClassResolvedSuper -> String
prologifyClassResolvedSuper (ClassResolvedSuper (Class c) (ResolvedSuper (Fqn fqn))) = prologifyClassResolvedSuper' c fqn

prologifyClassNamedSuper' :: Location -> String -> String
prologifyClassNamedSuper' l s = printf "kb_class_has_named_super( %s, \'%s\' )." (locationify l) s

prologifyClassNamedSuper :: ClassNamedSuper -> String
prologifyClassNamedSuper (ClassNamedSuper (Class c) (Token.SuperName (Token.Named name _))) = prologifyClassNamedSuper' c name

prologifyArgiForCall' :: Location -> Word -> Location -> String
prologifyArgiForCall' a i c = printf "kb_arg_i_for_call( %s, %u, %s )." (locationify a) i (locationify c)

prologifyArgiForCall :: ArgiForCall -> String
prologifyArgiForCall (ArgiForCall (Arg a) (ArgIndex i) (Call c)) = prologifyArgiForCall' a i c

prologify_ClassAnnotation' :: Location -> Location -> String
prologify_ClassAnnotation' c a = printf "kb_class_has_annotation( %s, %s )." (locationify c) (locationify a)

prologify_ClassAnnotation :: ClassAnnotation -> String
prologify_ClassAnnotation (ClassAnnotation (Class c) (Annotation a)) = prologify_ClassAnnotation' c a

prologify_KeywordArgForCall' ::  String -> Location -> Location -> String
prologify_KeywordArgForCall' kw a c = printf "kb_keyword_arg_for_call( %s, %s, %s )." (locationify a) kw (locationify c)

prologify_KeywordArgForCall :: KeywordArgForCall -> String
prologify_KeywordArgForCall (KeywordArgForCall (Keyword kw) (Arg a) (Call c)) = prologify_KeywordArgForCall' kw a c

prologify_CallableAnnotation' :: Location -> Location -> String
prologify_CallableAnnotation' c a = printf "kb_callable_has_annotation( %s, %s )." (locationify c) (locationify a)

prologify_CallableAnnotation :: CallableAnnotation -> String
prologify_CallableAnnotation (CallableAnnotation (Callable c) (Annotation a)) = prologify_CallableAnnotation' c a

prologify_ParamiOfCallable' :: Location -> Word -> Location -> String
prologify_ParamiOfCallable' p i c = printf "kb_param_i_of_callable( %s, %u, %s )." (locationify p) i (locationify c)

prologify_ParamiOfCallable :: ParamiOfCallable -> String
prologify_ParamiOfCallable (ParamiOfCallable (Param p) (ParamIndex i) (Callable c)) = prologify_ParamiOfCallable' p i c

locationify :: Location -> String
locationify l = let
    x = Location.lineStart l
    y = Location.colStart l
    z = Location.lineEnd l
    w = Location.colEnd l
    f = Location.filename l
    in printf "startloc_%u_%u_endloc_%u_%u_%s" x y z w f