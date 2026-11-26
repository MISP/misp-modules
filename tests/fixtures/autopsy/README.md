# Selected forensic fixtures

These are synthetic, non-personal fixtures, not claims of captured commercial
reports or complete Autopsy cases.

- history.csv models the English columns written by Autopsy's
  Export Selected Rows to CSV action. It includes a UTF-8 BOM, CSV quoting,
  formatted UTC times, extra producer/context columns and an unmapped column.
- cookies.csv models Chromium cookie rows with host values in Autopsy's URL
  column, a separate domain and last-access times shown in CET.
- selected.json exercises the documented misp-forensic-selected version 1
  interchange. The producer name is deliberately a generic example mobile
  parser. It covers all supported TSK profiles, an unknown artifact and
  case/device/source context.

Header/mapping references used when constructing the fixtures:

- [Autopsy ExportCSVAction.java](https://github.com/sleuthkit/autopsy/blob/cb3dacdcad67abe7cf863c74f10dcdb8e25a5c21/Core/src/org/sleuthkit/autopsy/directorytree/ExportCSVAction.java)
  exports displayed property names and values, with a CSV header and standard quoting.
- [Autopsy BlackboardArtifactNode.java](https://github.com/sleuthkit/autopsy/blob/cb3dacdcad67abe7cf863c74f10dcdb8e25a5c21/Core/src/org/sleuthkit/autopsy/datamodel/BlackboardArtifactNode.java)
  formats DATETIME fields using the user's selected display timezone.
- [Autopsy Chromium.java](https://github.com/sleuthkit/autopsy/blob/cb3dacdcad67abe7cf863c74f10dcdb8e25a5c21/RecentActivity/src/org/sleuthkit/autopsy/recentactivity/Chromium.java#L993-L1018)
  exports the cookie host key as TSK_URL and last access as TSK_DATETIME_ACCESSED.
- [Sleuth Kit English labels](https://github.com/sleuthkit/sleuthkit/blob/3dcb43668d811548206fbeaf5e0c9753202f672f/bindings/java/src/org/sleuthkit/datamodel/Bundle.properties)
  define URL, Date Accessed, Program Name, Referrer URL, Text, Message Type, etc.
- [Sleuth Kit TimeUtilities](https://github.com/sleuthkit/sleuthkit/blob/3dcb43668d811548206fbeaf5e0c9753202f672f/bindings/java/src/org/sleuthkit/datamodel/TimeUtilities.java)
  renders numeric zero as an unknown date rather than a 1970 event.

The JSON envelope is an importer-defined interchange, not a native Autopsy,
Cellebrite, Magnet, XRY or Oxygen report. A native commercial adapter needs a
redistributable, deidentified sample and a named maintainer before it can be
claimed or tested.
