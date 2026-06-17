ENTRY(main)

SECTIONS
{
	. = 0xC2000000;

	.text :
	{
		*(.text*)
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
