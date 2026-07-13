-- macOS URL-scheme handler for DIG links (#389/#503).
--
-- macOS delivers a clicked chia:// URL to a registered handler via the GetURL Apple Event
-- (NOT argv), so a bare CLI binary cannot be the handler directly. This tiny AppleScript app
-- (compiled by build-pkg.sh, its Info.plist given CFBundleURLTypes for the `chia` scheme)
-- receives the event and forwards the URL to `dig-node open`, which strictly validates it and
-- opens the local node serve URL.
--
-- `quoted form of` single-quote-escapes the URL, so even a crafted link cannot inject a shell
-- command; `dig-node open` re-validates + rejects metacharacters as a second layer.
on open location this_URL
	try
		do shell script "/usr/local/bin/dig-node open " & quoted form of this_URL
	end try
end open location
