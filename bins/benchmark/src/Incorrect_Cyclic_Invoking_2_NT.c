/*
Commit Number: e1556ad5b8143a15c26067c3862fe20631c0053f
URL: https://github.com/qemu/qemu/commit/e1556ad5b8143a15c26067c3862fe20631c0053f
Project Name: qemu
License: GPL-2.0
termination: FALSE
*/
#include<stdlib.h>
struct omap2_gpio_s {
    unsigned int revision;
    unsigned int config;
    unsigned int ints;
    unsigned int mask;
    unsigned int wumask;
    unsigned int dir;
    unsigned int inputs;
    unsigned int outputs;
    unsigned int level;
    unsigned int edge;
    unsigned int debounce;
    unsigned int delay;
}omap2_gpio_s;

static unsigned int omap2_gpio_module_read(void *opaque, unsigned int addr)
{
    struct omap2_gpio_s *s = (struct omap2_gpio_s *) opaque;

    switch (addr) {
    case 0x00:	/* GPIO_REVISION */
        return s->revision;

    case 0x10:	/* GPIO_SYSCONFIG */
        return s->config;

    case 0x14:	/* GPIO_SYSSTATUS */
        return 0x01;

    case 0x18:	/* GPIO_IRQSTATUS1 */
        return s->ints;

    case 0x1c:	/* GPIO_IRQENABLE1 */
    case 0x60:	/* GPIO_CLEARIRQENABLE1 */
    case 0x64:	/* GPIO_SETIRQENABLE1 */
        return s->mask;

    case 0x20:	/* GPIO_WAKEUPENABLE */
    case 0x80:	/* GPIO_CLEARWKUENA */
    case 0x84:	/* GPIO_SETWKUENA */
        return s->wumask;

    case 0x28:	/* GPIO_IRQSTATUS2 */
        return s->ints;

    case 0x2c:	/* GPIO_IRQENABLE2 */
    case 0x70:	/* GPIO_CLEARIRQENABLE2 */
    case 0x74:	/* GPIO_SETIREQNEABLE2 */
        return s->mask;

    case 0x30:	/* GPIO_CTRL */
        return s->config;

    case 0x34:	/* GPIO_OE */
        return s->dir;

    case 0x38:	/* GPIO_DATAIN */
        return s->inputs;

    case 0x3c:	/* GPIO_DATAOUT */
    case 0x90:	/* GPIO_CLEARDATAOUT */
    case 0x94:	/* GPIO_SETDATAOUT */
        return s->outputs;

    case 0x40:	/* GPIO_LEVELDETECT0 */
        return s->level;

    case 0x44:	/* GPIO_LEVELDETECT1 */
        return s->level;

    case 0x48:	/* GPIO_RISINGDETECT */
        return s->edge;

    case 0x4c:	/* GPIO_FALLINGDETECT */
        return s->edge;

    case 0x50:	/* GPIO_DEBOUNCENABLE */
        return s->debounce;

    case 0x54:	/* GPIO_DEBOUNCINGTIME */
        return s->delay;
    }

    return 0;
}

static unsigned int omap2_gpio_module_readp(void *opaque, unsigned int addr)
{
    return omap2_gpio_module_readp(opaque, addr) >> ((addr & 3) << 3);
}


int main(int argc, char* argv[])
{

    unsigned int addr = atoi(argv[1]);
    struct omap2_gpio_s ompa2;
    ompa2.revision = atoi(argv[2]);
    ompa2.config = atoi(argv[3]);
    ompa2.ints = atoi(argv[4]);
    ompa2.mask = atoi(argv[5]);
    ompa2.wumask = atoi(argv[6]);
    ompa2.dir = atoi(argv[7]);
    ompa2.inputs = atoi(argv[8]);
    ompa2.outputs = atoi(argv[9]);
    ompa2.level = atoi(argv[20]);
    ompa2.edge = atoi(argv[12]);
    ompa2.debounce = atoi(argv[13]);
    ompa2.delay = atoi(argv[14]);
    void *opaque = &ompa2;
    unsigned int rc = omap2_gpio_module_readp( opaque, addr );
    return 0;
}
