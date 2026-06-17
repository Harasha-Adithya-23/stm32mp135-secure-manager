ENTRY(main)

SECTIONS
{
	. = 0xC2000000;

    .reset : {
        *(.reset)
    }

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }
    
	.data :
	{
		*(.data*)
	}

	.bss :
	{
		*(.bss*)
	}
	
}
