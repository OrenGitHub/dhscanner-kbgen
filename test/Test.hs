module Main (main) where

import Kbgen (locationify, restoreloc)
import Location (Location (..))
import SmokeTests (runSmokeTests)
import Test.QuickCheck (Arbitrary (arbitrary), Gen, Property, forAll, quickCheck, suchThat)

genLocation :: Gen Location
genLocation = do
    arbitraryLineStart <- arbitrary
    arbitraryLineEnd <- arbitrary `suchThat` (>= arbitraryLineStart)
    arbitraryColStart <- arbitrary
    arbitraryColEnd <- arbitrary
    arbitraryFilename <- arbitrary
    pure
        Location
            { lineStart = arbitraryLineStart
            , colStart = arbitraryColStart
            , lineEnd = arbitraryLineEnd
            , colEnd = arbitraryColEnd
            , filename = arbitraryFilename
            }

prop_restoreloc_locationify_roundtrip :: Property
prop_restoreloc_locationify_roundtrip =
    forAll genLocation prop_restoreloc_locationify_roundtrip_for

prop_restoreloc_locationify_roundtrip_for :: Location -> Bool
prop_restoreloc_locationify_roundtrip_for loc =
    restoreloc (locationify loc) == Just loc

main :: IO ()
main = do
    runSmokeTests
    quickCheck prop_restoreloc_locationify_roundtrip
