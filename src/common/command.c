#include "command.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
    #include <conio.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <termios.h>
#endif

static command_t commands[MAX_COMMANDS];
static uint8_t command_count = 0;
static char input_buffer[256];
static uint16_t input_pos = 0;

#ifndef _WIN32
static struct termios original_term;
static uint8_t term_initialized = 0;

static void restore_terminal(void) {
    if (term_initialized) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_term);
    }
}
#endif

void cmd_init(void) {
    command_count = 0;
    input_pos = 0;
    memset(input_buffer, 0, sizeof(input_buffer));

#ifndef _WIN32
    /* Configuration du terminal en mode non-canonique */
    struct termios new_term;
    if (tcgetattr(STDIN_FILENO, &original_term) == 0) {
        new_term = original_term;
        new_term.c_lflag &= ~(ICANON | ECHO);
        new_term.c_cc[VMIN] = 0;
        new_term.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
        term_initialized = 1;
        atexit(restore_terminal);
    }

    /* Rendre stdin non-bloquant */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
#endif
}

void cmd_register(const char* name, const char* description, command_callback_t callback) {
    if (command_count >= MAX_COMMANDS) {
        return;
    }

    commands[command_count].name = name;
    commands[command_count].description = description;
    commands[command_count].callback = callback;
    command_count++;
}

void cmd_execute(const char* input) {
    char cmd_name[64];
    char args[192];

    /* Trim leading spaces */
    while (*input && isspace(*input)) input++;

    if (*input == '\0') return;

    /* Parse command name */
    uint8_t i = 0;
    while (*input && !isspace(*input) && i < 63) {
        cmd_name[i++] = *input++;
    }
    cmd_name[i] = '\0';

    /* Skip spaces */
    while (*input && isspace(*input)) input++;

    /* Copy arguments */
    strncpy(args, input, 191);
    args[191] = '\0';

    /* Find and execute command */
    for (uint8_t j = 0; j < command_count; j++) {
        if (strcmp(commands[j].name, cmd_name) == 0) {
            commands[j].callback(args);
            return;
        }
    }

    printf("Unknown command: %s (type 'help' for list)\n", cmd_name);
}

void cmd_help(void) {
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    Available Commands                      ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");

    for (uint8_t i = 0; i < command_count; i++) {
        printf("║ %-15s : %-41s║\n", commands[i].name, commands[i].description);
    }

    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

void cmd_poll_stdin(void) {
#ifdef _WIN32
    if (_kbhit()) {
        int ch = _getch();

        if (ch == '\r' || ch == '\n') {
            printf("\n");
            input_buffer[input_pos] = '\0';
            if (input_pos > 0) {
                cmd_execute(input_buffer);
                input_pos = 0;
            }
            printf("> ");
            fflush(stdout);
        } else if (ch == '\b' || ch == 127) {
            if (input_pos > 0) {
                input_pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (ch >= 32 && ch < 127 && input_pos < 255) {
            input_buffer[input_pos++] = (char)ch;
            printf("%c", ch);
            fflush(stdout);
        }
    }
#else
    char ch;
    int n = read(STDIN_FILENO, &ch, 1);

    if (n > 0) {
        if (ch == '\n' || ch == '\r') {
            printf("\n");
            input_buffer[input_pos] = '\0';
            if (input_pos > 0) {
                cmd_execute(input_buffer);
                input_pos = 0;
            }
            printf("> ");
            fflush(stdout);
        } else if (ch == 127 || ch == '\b') {
            if (input_pos > 0) {
                input_pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (ch >= 32 && ch < 127 && input_pos < 255) {
            input_buffer[input_pos++] = ch;
            printf("%c", ch);
            fflush(stdout);
        }
    }
#endif
}
