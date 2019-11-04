# IDA Android Kernel Symbolizer
IDA Android Kernel Symbolizer is an IDA Python script that allows you to import symbols from /proc/kallsyms output into an unlabelled Android kernel, typically extracted from a boot image.

# How does it work?
First, the script prompts you to open a file containing the contents of /proc/kallsyms output. The file should contain text that looks something like this:

```
ffffff9918280000 t _head
ffffff9918280000 T _text
ffffff9918280040 t pe_header
ffffff9918280044 t coff_header
ffffff9918280058 t optional_header
ffffff9918280070 t extra_header_fields
[...]
```

After the file is opened, the script parses the symbol entries and utilizes the `_text` symbol (aka. the kernel .text base address) to convert the kASLR'd virtual addresses into slides, and adds them into lookup tables.

Finally, it runs through the function lookup table it just constructed to mark the address as code and create a subroutine in IDA if it does not already exists and labels it. It then does the same for the data lookup table, however it only labels the address and does not mark it as code or create a subroutine there.

# Notes
- Running this script is generally fairly fast (under 20 seconds), however it will trigger IDA's Auto-Analysis engine to kick in, and this can take up to 5 minutes from our tests. During this time, IDA might be sluggish.

# License
This script is licensed under the [MIT license](LICENSE).
