# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## 1.2.2 - 2024-09-02
### Fixed 
- Handling flat response (without a nested `:challenge` object) in validation

## 1.2.1 - 2024-09-02
### Fixed 
- More robust handling of some encoding edge cases
- URL parameters are now decoded before being extracted into a map during salt validation

## 1.2.0 - 2024-09-02
### Fixed 
- Added missing test hook for `calculate-expiration-offset`
- Challenge expiration is now more pure and deterministic, some related petty errors fixed
### Added
- Some extra tests, particularly for various challenge response configurations
- Additional parameters for `create-challenge` - `:ttl` and `:current-time`
### Changed
- Default max-number is now cast to an integer (1e6 is a `Double` by default)

## 1.1.0 - 2024-09-01
### Fixed 
- Generation of expire time value

### Changed 
- Made the generation of challenge expiration offset 'more pure'

## 1.0.2 - 2024-09-01
### Changed
- Made some functions and constants private

## 1.0.1 - 2024-09-01
### Fixed 
- `java.util.Base64` import not wrapped in feature constraint properly

## 1.0.0 - 2024-09-01
### Added 
- Challenge and signature verification.

### Fixed
- Bugs in decoding functionality.

### Changed 
- Added `^:const` annotations for default values in `core` namespace.
- Expanded and corrected documentation.

## 0.1.1 - 2024-08-29
### Changed
- Updated the project name so that it can be published to Clojars

## [0.1.0] - 2024-08-29
### Added
- Added a function to create challenge messages that the client can process.
