# flare-qdb Notes

## Acknowledgements

* FLARE Team - Encouraging and facilitating innovation
* Invisigoth - Vivisect + support and incorporating fixes
* Willi Ballenthin - Predictably excellent Python feedback
* Moritz Raabe - Thoughtful pre-release testing and user experience feedback
* zv1n (Terry Meacham) - Providing a sounding board and useful Pythonic feedback

## Future Possibilities

There are a few Vivisect capabilities that may be worth adding.

### Hardware breakpoints

Hardware breakpoints are called "watchpoints" in Vivisect. It looks like
`archAddWatchpoint()` adds them:

```archAddWatchpoint(self, address, size=4, perms="rw")```

Perhaps syntax along the lines of:

```watchb(addr) # 1 byte```

```watchw(addr) # 2 bytes```

```watchd(addr) # 4 bytes```

### Pagewatches

Vivisect has a concept of a "pagewatch" which can watch accesses within a page.
Could watch monitor allocations with this to detect jumping into allocated
code.
