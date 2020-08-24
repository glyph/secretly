on getPassword(prompt, title)
    set keychainIcon to POSIX file ¬
        ("/System/Applications/Utilities/Keychain Access.app" & ¬
        "/Contents/Resources/AppIcon.icns")

    display dialog prompt ¬
        default answer "" ¬
        with hidden answer ¬
        with icon keychainIcon ¬
        with title title

    return result's text returned
end getPassword

on run argv
    set thePrompt to argv's item 1
    set theTitle to argv's item 2
    return my getPassword(thePrompt, theTitle)
end run