#define GPIOD_BASE          0x50005000
#define GPIOD_MODER         (*(volatile unsigned int *)(GPIOD_BASE + 0x00))
#define GPIOD_AFRL          (*(volatile unsigned int *)(GPIOD_BASE + 0x20))

#define UART_BASE           0x40010000
#define USART_CR1           (*(volatile unsigned int *)(UART_BASE + 0x00))
#define USART_BRR           (*(volatile unsigned int *)(UART_BASE + 0x0C))
#define USART_ISR           (*(volatile unsigned int *)(UART_BASE + 0x1C))
#define USART_TDR           (*(volatile unsigned int *)(UART_BASE + 0x28))

__attribute__((naked, section(".reset"))) void reset_handler(void)
{
    __asm__("b main");
}

void clock_init(void)
{
    /* Clocks already enabled by TF-A/U-Boot, just settle */
    for(volatile int i = 0; i < 100; i++);
}

void gpio_uart_init(void)
{
    /* Exact values read from Linux via /dev/mem */
    GPIOD_MODER = 0xAEAA2ABA;
    GPIOD_AFRL  = 0x08E3D04D;
}

void uart_init(void)
{
    USART_CR1 = 0;
    USART_BRR = 0x22C;
    USART_CR1 = 0x2000002F;
}

void uart_putc(char c)
{
    while(!(USART_ISR & (1 << 7)));
    USART_TDR = c;
}

void uart_puts(char *s)
{
    while(*s)
        uart_putc(*s++);
}

void delay(void)
{
    for(volatile unsigned int i = 0; i < 10000000; i++);
}

int main(void)
{
    clock_init();
    gpio_uart_init();
    uart_init();

    uart_puts("\r\n");
    uart_puts("====================\r\n");
    uart_puts("Secure Manager Start\r\n");
    uart_puts("====================\r\n");

    delay();
    return 0;
}
