#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_CONTROLS 100
#define MAX_ELEM_SIZE 1024

struct snd_ctl_elem_value {
    uint32_t id;
    uint32_t value;
};

struct user_element {
    uint32_t elem_data_size;
    uint8_t elem_data[MAX_ELEM_SIZE];
};

struct snd_kcontrol {
    struct user_element *private_data;
};

static struct snd_kcontrol controls[MAX_CONTROLS];

static int snd_ctl_elem_user_put(struct snd_kcontrol *kcontrol,
                                 struct snd_ctl_elem_value *ucontrol)
{
    int change;
    struct user_element *ue = kcontrol->private_data;
    
    change = memcmp(&ucontrol->value, ue->elem_data, ue->elem_data_size) != 0;
    if (change)
        memcpy(ue->elem_data, &ucontrol->value, ue->elem_data_size);
    return change;
}

static int snd_ctl_elem_user_get(struct snd_kcontrol *kcontrol,
                                 struct snd_ctl_elem_value *ucontrol)
{
    struct user_element *ue = kcontrol->private_data;
    
    memcpy(&ucontrol->value, ue->elem_data, ue->elem_data_size);
    return 0;
}

static void init_control(int index, uint32_t id, uint32_t value, uint32_t size)
{
    controls[index].private_data = malloc(sizeof(struct user_element));
    controls[index].private_data->elem_data_size = size;
    memcpy(controls[index].private_data->elem_data, &value, size);
}

int main()
{
    init_control(0, 1, 0x12345678, sizeof(uint32_t));
    
    struct snd_ctl_elem_value val = {1, 0x87654321};
    snd_ctl_elem_user_put(&controls[0], &val);
    
    struct snd_ctl_elem_value get_val = {0};
    snd_ctl_elem_user_get(&controls[0], &get_val);
    
    printf("Value: 0x%x\n", get_val.value);
    
    free(controls[0].private_data);
    return 0;
}