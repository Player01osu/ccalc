#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>

#define ARENA_DEBUG
#define ARENA_IMPLEMENTATION
#define ARENA_SUPPRESS_MALLOC_WARN
#include "arena.h"

/* Memory is cheap */
#define ARENA_SIZE 1024 * 64
#define READ_BUF_SIZE 1024
#define TOKEN_VEC_SIZE 2
#define INPUT_BUF_SIZE 1024 / 2

#define unreachable() \
	fprintf(stderr, "%s:%d:unreachable", __FILE__, __LINE__); \
	exit(1);

/* Owned string view */
typedef struct TokenString {
	char *str;
	size_t len;
} TokenString;

typedef struct Span {
	size_t start_row;
	size_t start_col;
	size_t end_row;
	size_t end_col;
} Span;

// clang-format off
typedef enum TokenKind {
	TOKEN_NUM,         /* '0'-'9'     */
	TOKEN_IDENT,       /* 'a'-'Z'|'_' */
	TOKEN_LEFT_PAREN,  /* '('         */
	TOKEN_RIGHT_PAREN, /* ')'         */
	TOKEN_ASSIGNMENT,  /* '='         */
	TOKEN_TICK,        /* '''         */
	TOKEN_COMMA,       /* ','         */

	TOKEN_EQUALS,      /* '=='        */
	TOKEN_PLUS,        /* '+'         */
	TOKEN_MINUS,       /* '-'         */
	TOKEN_MULT,        /* '*'         */
	TOKEN_DIV,         /* '/'         */

	TOKEN_EOL,         /* '\n'|'\r'   */
	TOKEN_EOF,         /* '\0'        */
	TOKEN_ILLEGAL,
} TokenKind;
// clang-format on

typedef union TokenData {
	double num;
	TokenString string;
} TokenData;

typedef struct Token {
	TokenKind kind;
	TokenData data;
	Span span;
} Token;

typedef struct Node Node;
typedef struct Expr Expr;

typedef struct Ident {
	TokenString token_string;
} Ident;

typedef struct Idents {
	Ident *idents;
	size_t len;
} Idents;

typedef struct Exprs {
	Expr **exprs;
	size_t len;
} Exprs;

typedef struct Func {
	Ident name;
	Exprs args;
	bool prime;
} Func;

typedef struct AssignFunc {
	Ident name;
	Idents args;
	Expr *expr;
} AssignFunc;

typedef struct Assign {
	Ident name;
	Expr *expr;
} Assign;

typedef enum Operator {
	OPERATOR_PLUS,
	OPERATOR_MINUS,
	OPERATOR_MULT,
	OPERATOR_DIV,
} Operator;

typedef struct OperatorStack {
	Operator *vec;
	size_t size;
	size_t len;
} OperatorStack;

typedef struct Infix {
	Expr *expr_a;
	Expr *expr_b;
	Operator operator;
} Infix;

typedef struct Paren {
	Expr *expr;
} Paren;

typedef enum ExprKind {
	EXPR_NUM,
	EXPR_IDENT,
	EXPR_PAREN,
	EXPR_FUNC,
	EXPR_INFIX,
} ExprKind;

typedef union ExprData {
	double num;
	Ident ident;
	Func func;
	Infix infix;
	Paren paren;
} ExprData;

struct Expr {
	ExprKind kind;
	ExprData data;
};

typedef enum NodeKind {
	NODE_ASSIGN,
	NODE_ASSIGN_FUNC,
	NODE_EXPR,
	NODE_EOF,
} NodeKind;

typedef union NodeData {
	Assign assign;
	AssignFunc assign_func;
	Expr *expr;
} NodeData;

struct Node {
	NodeKind kind;
	NodeData data;
};

typedef struct ReadBuf {
	char buf[READ_BUF_SIZE];
	size_t idx;
} ReadBuf;

typedef struct Lexer {
	const char *src;

	const char *p;
	size_t len_remaining;

	size_t row;
	size_t col;

	Arena *arena;
	ReadBuf read_buf;
} Lexer;

typedef struct Parser {
	Lexer lexer;

	bool error;
	size_t scope_level;
	Token token_vec[TOKEN_VEC_SIZE];
	Arena *arena;
} Parser;

typedef enum PostfixTokenKind {
	POSTFIX_TOKEN_NUM,
	POSTFIX_TOKEN_VAR,
	POSTFIX_TOKEN_OPERATOR,
} PostfixTokenKind;

typedef union PostfixTokenData {
	double num;
	TokenString var;
	Operator operator;
} PostfixTokenData;

typedef struct PostfixToken {
	PostfixTokenKind kind;
	PostfixTokenData data;
} PostfixToken;

typedef struct Postfix {
	PostfixToken *tokens;
	size_t len;
	size_t size;
} Postfix;

typedef enum SymValueKind {
	SYM_VALUE_SYM,
	SYM_VALUE_NUM,
	SYM_VALUE_POSTFIX,
	SYM_VALUE_NIL,
} SymValueKind;

typedef union SymValueData {
	TokenString sym;
	double num;
	Postfix postfix;
} SymValueData;

typedef struct SymValue {
	SymValueKind kind;
	SymValueData data;
} SymValue;

typedef struct SymKV {
	TokenString token_string;
	SymValue value;
} SymKV;

typedef struct SymMap {
	SymKV *kvs;
	size_t len;
	size_t size;
	Arena *arena;
} SymMap;

typedef struct Env {
	SymMap sym_map;
	Arena *arena;
} Env;

void lexer_init(Lexer *lexer, const char *src, Arena *arena)
{
	lexer->src = src;
	lexer->p = src;
	lexer->len_remaining = strlen(src);

	lexer->row = 1;
	lexer->col = 0;

	lexer->arena = arena;
	lexer->read_buf = (ReadBuf){
		.buf = { 0 },
		.idx = 0,
	};
}

const char *lexer_bump(Lexer *lexer)
{
	if (lexer->len_remaining == 0) return NULL;

	if (*lexer->p == '\n') {
		++lexer->row;
		lexer->col = 0;
	} else {
		++lexer->col;
	}

	--lexer->len_remaining;
	return lexer->p++;
}

const char *lexer_peak(Lexer *lexer)
{
	if (lexer->len_remaining == 0) return NULL;

	return lexer->p;
}

void lexer_consume_equals(Lexer *lexer, TokenKind *kind)
{
	const char *c = lexer_peak(lexer);
	if (c == NULL) {
		*kind = TOKEN_ILLEGAL;
		return;
	}

	if (*lexer_peak(lexer) == '=') {
		lexer_bump(lexer);
		*kind = TOKEN_EQUALS;
	} else {
		*kind = TOKEN_ASSIGNMENT;
	}
}

bool is_ident(char c)
{
	return isalnum(c) || c == '_';
}

TokenString token_string_create(Arena *arena, ReadBuf *read_buf)
{
	size_t len = read_buf->idx;
	char *str = read_buf->buf;
	char *arena_str = (char *)arena_alloc(arena, sizeof(char) * (len + 1));
	memcpy(arena_str, str, len + 1);
	return (TokenString){
		.str = arena_str,
		.len = len,
	};
}

void token_string_print(TokenString *token_string)
{
	fwrite(token_string->str, token_string->len, sizeof(char), stdout);
}

int token_string_cmp(TokenString *a, TokenString *b)
{
	size_t i;
	for (i = 0; i < a->len || i < b->len; ++i) {
		if (a->str[i] - b->str[i] != 0) { return a->str[i] - b->str[i]; }
	}
	return a->str[i] - b->str[i];
}

void token_string_println(TokenString *token_string)
{
	token_string_print(token_string);
	fputc('\n', stdout);
}

bool read_buf_increment(ReadBuf *read_buf, char c)
{
	if (read_buf->idx >= READ_BUF_SIZE) return false;

	read_buf->buf[read_buf->idx] = c;
	++(read_buf->idx);
	return true;
}

void read_buf_clear(ReadBuf *read_buf)
{
	while (read_buf->idx) {
		read_buf->buf[read_buf->idx] = '\0';
		--(read_buf->idx);
	}
}

void lexer_consume_digit(Lexer *lexer, TokenKind *kind, TokenData *data, char c)
{
	const char *peak;

	read_buf_increment(&lexer->read_buf, c);
	*kind = TOKEN_NUM;

	if ((peak = lexer_peak(lexer)) != NULL) {
		c = *peak;

		while (isdigit(c) || c == '.') {
			read_buf_increment(&lexer->read_buf, c);
			lexer_bump(lexer);

			if ((peak = lexer_peak(lexer)) == NULL) break;
			c = *peak;
		}
	}
	data->num = atof(lexer->read_buf.buf);
	read_buf_clear(&lexer->read_buf);
}

void lexer_consume_ident(Lexer *lexer, TokenKind *kind, TokenData *data, char c)
{
	if (isdigit(c)) {
		lexer_consume_digit(lexer, kind, data, c);
		return;
	}

	const char *peak;

	read_buf_increment(&lexer->read_buf, c);
	*kind = TOKEN_IDENT;
	if ((peak = lexer_peak(lexer)) != NULL) {
		c = *peak;

		while (is_ident(c)) {
			read_buf_increment(&lexer->read_buf, c);
			lexer_bump(lexer);

			if ((peak = lexer_peak(lexer)) == NULL) break;
			c = *peak;
		}
	}

	data->string = token_string_create(lexer->arena, &lexer->read_buf);
	read_buf_clear(&lexer->read_buf);
}

Token lexer_next(Lexer *lexer)
{
#define K(tk) token.kind = tk;
	Token token = { 0 };
	const char *c = lexer_bump(lexer);
	if (c == NULL) {
		token.kind = TOKEN_EOF;
		return token;
	}

	size_t start_row = lexer->row;
	size_t start_col = lexer->col;

	switch (*c) {
	case '+': K(TOKEN_PLUS); break;
	case '-': K(TOKEN_MINUS); break;
	case '*': K(TOKEN_MULT); break;
	case '/': K(TOKEN_DIV); break;
	case '(': K(TOKEN_LEFT_PAREN); break;
	case ')': K(TOKEN_RIGHT_PAREN); break;
	case '\'': K(TOKEN_TICK); break;
	case ',': K(TOKEN_COMMA); break;
	case '\n':
	case '\r': K(TOKEN_EOL); break;
	case '\t':
	case ' ': return lexer_next(lexer);
	case '=': {
		lexer_consume_equals(lexer, &token.kind);
	} break;
	default: {
		lexer_consume_ident(lexer, &token.kind, &token.data, *c);
	} break;
	}

	size_t end_row = lexer->row;
	size_t end_col = lexer->col;

	token.span = (Span){
		.start_row = start_row,
		.start_col = start_col == 0 ? 1 : start_col,
		.end_row = end_row,
		.end_col = end_col,
	};

	return token;
#undef K
}

Lexer lexer_clone(Lexer *lexer)
{
	// TODO: This clones the read_buf
	//
	// read_buf should be reused
	Lexer clone = { 0 };
	memcpy(&clone, lexer, sizeof(Lexer));
	return clone;
}

Token lexer_peak_token(Lexer *lexer)
{
	Lexer clone = lexer_clone(lexer);

	return lexer_next(&clone);
}

void span_print(Span span)
{
	printf(" (%ld,%ld) => (%ld,%ld)\n", span.start_row, span.start_col, span.end_row,
	       span.end_col);
}

void token_print(Token *token)
{
#define C(x)                                                                                       \
	case x: {                                                                                  \
		printf(#x);                                                                        \
		span_print(token->span);                                                           \
	} break;
	// clang-format off
	switch (token->kind) {
	case TOKEN_NUM: {
		printf("TOKEN_NUM => %f", token->data.num);
		span_print(token->span);
	} break;
	case TOKEN_IDENT: {
		printf("TOKEN_IDENT => ");
		token_string_print(&token->data.string);
		span_print(token->span);
	} break;
	C(TOKEN_PLUS)
	C(TOKEN_MINUS)
	C(TOKEN_MULT)
	C(TOKEN_DIV)
	C(TOKEN_LEFT_PAREN)
	C(TOKEN_RIGHT_PAREN)
	C(TOKEN_TICK)
	C(TOKEN_ASSIGNMENT)
	C(TOKEN_COMMA)
	C(TOKEN_EQUALS)
	C(TOKEN_ILLEGAL)
	C(TOKEN_EOL)
	C(TOKEN_EOF)
	}
// clang-format on
#undef C
}

void parser_pull_peak(Parser *parser)
{
	Lexer clone = lexer_clone(&parser->lexer);
	Token *token_vec = parser->token_vec;
	for (size_t i = 0; i < TOKEN_VEC_SIZE; ++i) { token_vec[i] = lexer_next(&clone); }
}

void parser_init(Parser *parser, const char *src, Arena *arena)
{
	Lexer lexer = { 0 };
	lexer_init(&lexer, src, arena);

	parser->error = false;
	parser->scope_level = 0;
	parser->lexer = lexer;
	parser->arena = arena;
	parser_pull_peak(parser);
}

Token parser_bump(Parser *parser)
{
	Token token = lexer_next(&parser->lexer);
	parser_pull_peak(parser);
	return token;
}

Token parser_peak(Parser *parser)
{
	return lexer_peak_token(&parser->lexer);
}

bool is_operator(TokenKind kind)
{
#define E(x) kind == x
	return E(TOKEN_PLUS) || E(TOKEN_MINUS) || E(TOKEN_MULT) || E(TOKEN_DIV);
#undef E
}

bool is_end_ident(TokenKind kind)
{
#define E(x) kind == x
	return E(TOKEN_ASSIGNMENT) || E(TOKEN_RIGHT_PAREN) || E(TOKEN_EQUALS) || E(TOKEN_COMMA) ||
	       E(TOKEN_EOL) || E(TOKEN_EOF);
#undef E
}

bool is_end_num(TokenKind kind)
{
#define E(x) kind == x
	return E(TOKEN_RIGHT_PAREN) || E(TOKEN_EQUALS) || E(TOKEN_EOL) || E(TOKEN_COMMA) ||
	       E(TOKEN_EOF);
#undef E
}

#define parser_error(parser, msg) _parser_error(parser, msg, __LINE__)
void _parser_error(Parser *parser, const char *msg, size_t line)
{
	fprintf(stderr, "ERROR:%lu: %s\n", line, msg);
	fprintf(stderr, "ERROR: Stopped parsing at '%s'\n", parser->lexer.p);
	parser->error = true;
}

Operator cook_operator(Token *token)
{
#define C(x) \
	case TOKEN_##x: return OPERATOR_##x; break;
// clang-format off
	switch (token->kind) {
	C(PLUS)
	C(MINUS)
	C(MULT)
	C(DIV)
	default: {
		fprintf(stderr, "Unexpected token: should be operator; got %d", token->kind);
		exit(1);
	}
	}
// clang-format on
#undef C
}

Expr *parse_num(Parser *parser, Token *token);

Expr *parse_ident(Parser *parser, Token *token);

Expr *parse_negative(Parser *parser);

Expr *parse_paren(Parser *parser);

Exprs parse_args(Parser *parser);

Expr *parse_expr(Parser *parser, Token *token)
{
	// TODO: Check infix here instead
	switch (token->kind) {
	case TOKEN_MINUS: {
		return parse_negative(parser);
	} break;
	case TOKEN_NUM: {
		return parse_num(parser, token);
	} break;
	case TOKEN_IDENT: {
		return parse_ident(parser, token);
	} break;
	case TOKEN_LEFT_PAREN: {
		return parse_paren(parser);
	} break;
	default: {
		parser_error(parser, "Unexpected start of expr");
		return NULL;
	}
	}
}

// MINUS (IDENT|NUM) ...
//       ^           ^
//       start       end
Expr *parse_negative(Parser *parser)
{
	Token token = parser_bump(parser);
	switch (token.kind) {
		case TOKEN_NUM: {
			token.data.num *= -1;
			return parse_num(parser, &token);
		} break;
		case TOKEN_IDENT: {
			Expr *infix = arena_alloc(parser->arena, sizeof(Expr));
			Expr *expr_a = arena_alloc(parser->arena, sizeof(Expr));
			Expr *expr_b = arena_alloc(parser->arena, sizeof(Expr));
			expr_a->kind = EXPR_NUM;
			expr_a->data.num = -1.0f;

			expr_b->kind = EXPR_IDENT;
			expr_b->data.ident.token_string = token.data.string;

			infix->kind = EXPR_INFIX;
			infix->data.infix = (Infix) {
				.expr_a = expr_a,
				.expr_b = expr_b,
				.operator = OPERATOR_MULT,
			};

			return infix;
		} break;
		default: {
			parser_error(parser, "Unexpected token");
		} break;
	}
}


// EXPR OPERATOR EXPR ...
//      ^             ^
//      start         end
Expr *parse_infix(Parser *parser, Expr *lhs)
{
	Expr *expr = arena_alloc(parser->arena, sizeof(Expr));

	Token next = parser_bump(parser);
	if (!is_operator(next.kind)) { parser_error(parser, "Expected operator"); }

	Operator operator = cook_operator(&next);

	next = parser_bump(parser);
	Expr *rhs = parse_expr(parser, &next);

	expr->kind = EXPR_INFIX;
	expr->data.infix = (Infix){ .expr_a = lhs, .expr_b = rhs, .operator = operator, };
	return expr;
}

// NUM ...
// ^   ^
Expr *parse_num(Parser *parser, Token *token)
{
	if (token->kind != TOKEN_NUM) { parser_error(parser, "Expected num"); }

	TokenKind peak_kind = parser->token_vec[0].kind;

	Expr *expr = arena_alloc(parser->arena, sizeof(Expr));
	expr->kind = EXPR_NUM;
	expr->data.num = token->data.num;

	if (is_operator(peak_kind)) { return parse_infix(parser, expr); }

	if (!is_end_num(peak_kind)) {
		parser_error(parser, "Unexpected token; expected end of num");
	}

	return expr;
}

Ident cook_ident(Token *token)
{
	return (Ident){
		.token_string = token->data.string,
	};
}

bool is_func_arg(TokenKind kind)
{
#define K(x) kind == x
	return K(TOKEN_IDENT);
#undef K
}

// IDENT LEFT_PAREN EXPR* RIGHT_PAREN ...
//       ^                            ^
//       start                        end
Expr *parse_func(Parser *parser, Ident ident)
{
	assert(parser_bump(parser).kind == TOKEN_LEFT_PAREN);
	Exprs args = parse_args(parser);
	if (parser_bump(parser).kind != TOKEN_RIGHT_PAREN) {
		parser_error(parser, "Expected right paren");
	}
	Expr *expr = arena_alloc(parser->arena, sizeof(Expr));

	expr->kind = EXPR_FUNC;
	expr->data.func = (Func){
		.name = ident,
		.args = args,
	};

	if (is_operator(parser->token_vec[0].kind)) { return parse_infix(parser, expr); }

	return expr;
}

// IDENT EXPR ...
//       ^    ^
//     start  end
Expr *parse_ident(Parser *parser, Token *token)
{
	Token *peak = &parser->token_vec[0];
	switch (peak->kind) {
	case TOKEN_TICK: {
		if (parser->token_vec[1].kind != TOKEN_LEFT_PAREN) {
			parser_error(parser, "Expected left paren");
			return NULL;
		}
		parser_bump(parser);
		Expr *func = parse_func(parser, cook_ident(token));
		func->data.func.prime = true;
		return func;
	} break;
	case TOKEN_LEFT_PAREN: {
		return parse_func(parser, cook_ident(token));
	} break;
	default: {
		Expr *expr = arena_alloc(parser->arena, sizeof(Expr));

		expr->kind = EXPR_IDENT;
		expr->data.ident = cook_ident(token);
		if (is_operator(peak->kind)) { return parse_infix(parser, expr); }

		if (!is_end_ident(peak->kind)) {
			parser_error(parser, "Unexpected token; expected end ident");
		}
		return expr;
	}
	}
}

// LEFT_PAREN EXPR RIGHT_PAREN ...
//            ^                ^
//            start            end
Expr *parse_paren(Parser *parser)
{
	++parser->scope_level;
	Token next = parser_bump(parser);
	Expr *expr = arena_alloc(parser->arena, sizeof(Expr));
	expr->kind = EXPR_PAREN;
	expr->data.paren = (Paren){
		.expr = parse_expr(parser, &next),
	};
	next = parser_bump(parser);
	if (next.kind != TOKEN_RIGHT_PAREN) {
		parser_error(parser, "Unexpected token; expect a close paren");
	}
	--parser->scope_level;

	Token *peak = &parser->token_vec[0];
	if (is_operator(peak->kind)) { return parse_infix(parser, expr); }

	return expr;
}

bool is_idents(Exprs exprs)
{
	for (size_t i = 0; i < exprs.len; ++i) {
		if (exprs.exprs[i]->kind != EXPR_IDENT) { return false; }
	}

	return true;
}

Idents exprs_to_idents(Arena *arena, Exprs exprs)
{
	assert(is_idents(exprs));
	Ident *idents = arena_alloc(arena, sizeof(Ident) * exprs.len);

	for (size_t i = 0; i < exprs.len; ++i) { idents[i] = exprs.exprs[i]->data.ident; }

	return (Idents){
		.idents = idents,
		.len = exprs.len,
	};
}

// IDENT LEFT_PAREN (EXPR,)* RIGHT_PAREN
//                  ^        ^
//                  starts   ends
Exprs parse_args(Parser *parser)
{
	size_t size = 4;
	size_t len = 0;
	Expr **expr_vec = malloc(sizeof(Expr *) * size);

	while (parser->token_vec[0].kind != TOKEN_RIGHT_PAREN) {
		Token token = parser_bump(parser);
		expr_vec[len++] = parse_expr(parser, &token);
		if (len >= size) {
			size *= 2;
			expr_vec = realloc(expr_vec, sizeof(Expr *) * size);
		}

		Token *peak = &parser->token_vec[0];
		if (peak->kind != TOKEN_COMMA && peak->kind != TOKEN_RIGHT_PAREN) {
			parser_error(parser, "Unexpected token");
		}

		if (peak->kind == TOKEN_COMMA) { parser_bump(parser); }
	}

	Expr **expr_arena = arena_alloc(parser->arena, sizeof(Expr *) * len);
	memcpy(expr_arena, expr_vec, sizeof(Expr *) * len);
	free(expr_vec);

	Exprs exprs = (Exprs){
		.exprs = expr_arena,
		.len = len,
	};
	return exprs;
}

// TODO: Refactor this!
//
// !! could be func call !!
// IDENT LEFT_PAREN IDENT* RIGHT_PAREN ASSIGNMENT EXPR ...
//       ^                                             ^
//       starts                                        ends
Node parse_assign_func(Parser *parser, Ident ident)
{
	assert(parser_bump(parser).kind == TOKEN_LEFT_PAREN);
	Exprs exprs = parse_args(parser);
	if (parser_bump(parser).kind != TOKEN_RIGHT_PAREN) {
		parser_error(parser, "Expected right paren");
	}

	if (is_idents(exprs) && parser->token_vec[0].kind == TOKEN_ASSIGNMENT) {
		assert(parser_bump(parser).kind == TOKEN_ASSIGNMENT);
		Token token = parser_bump(parser);
		Expr *expr = parse_expr(parser, &token);
		Idents idents = exprs_to_idents(parser->arena, exprs);

		AssignFunc assign_func = (AssignFunc){
			.name = ident,
			.args = idents,
			.expr = expr,
		};

		return (Node){ .kind = NODE_ASSIGN_FUNC,
			       .data = (NodeData){ .assign_func = assign_func } };
	} else {
		Expr *func = arena_alloc(parser->arena, sizeof(Expr));
		func->kind = EXPR_FUNC;
		func->data.func = (Func){
			.name = ident,
			.args = exprs,
		};

		// If next token is infix, parse as such
		if (is_operator(parser->token_vec[0].kind)) {
			Expr *expr = parse_infix(parser, func);
			if (parser->token_vec[0].kind != TOKEN_EOL &&
			    parser->token_vec[0].kind != TOKEN_EOF) {
				parser_error(parser, "Expected end of node");
			}
			return (Node){ .kind = NODE_EXPR, .data = (NodeData){ .expr = expr } };
		}
		if (parser->token_vec[0].kind != TOKEN_EOL &&
		    parser->token_vec[0].kind != TOKEN_EOF) {
			parser_error(parser, "Expected end of node");
		}

		return (Node){ .kind = NODE_EXPR, .data = (NodeData){ .expr = func } };
	}
}

// IDENT ASSIGNMENT EXPR ...
//       ^               ^
//       start           end
Node parse_assign(Parser *parser, Ident ident)
{
	assert(parser_bump(parser).kind == TOKEN_ASSIGNMENT);
	Token token = parser_bump(parser);
	Expr *expr = parse_expr(parser, &token);
	Assign assign = (Assign){
		.name = ident,
		.expr = expr,
	};
	return (Node){ .kind = NODE_ASSIGN, .data = (NodeData){ .assign = assign } };
}

Node parser_next(Parser *parser)
{
	Token token = parser_bump(parser);
	Node node = { 0 };

	switch (token.kind) {
	case TOKEN_MINUS: {
		node.kind = NODE_EXPR;
		node.data.expr = parse_negative(parser);
	} break;
	case TOKEN_NUM: {
		node.kind = NODE_EXPR;
		node.data.expr = parse_num(parser, &token);
	} break;
	case TOKEN_IDENT: {
		if (parser->token_vec[0].kind == TOKEN_LEFT_PAREN) {
			return parse_assign_func(parser, cook_ident(&token));
		} else if (parser->token_vec[0].kind == TOKEN_ASSIGNMENT) {
			return parse_assign(parser, cook_ident(&token));
		} else {
			node.kind = NODE_EXPR;
			node.data.expr = parse_ident(parser, &token);
		}
	} break;
	case TOKEN_LEFT_PAREN: {
		node.kind = NODE_EXPR;
		node.data.expr = parse_paren(parser);
	} break;
	case TOKEN_EOL: {
		return parser_next(parser);
	} break;
	case TOKEN_EOF: {
		node.kind = NODE_EOF;
		return node;
	} break;
	default: {
		parser_error(parser, "Unexpected start of node");
	}
	}

	return node;
}

void sym_map_init(SymMap *sym_map, Arena *arena)
{
	sym_map->len = 0;
	sym_map->size = 16;
	sym_map->kvs = malloc(sizeof(SymKV) * sym_map->size);
	sym_map->arena = arena;
}

void sym_map_destroy(SymMap *sym_map)
{
	sym_map->len = 0;
	sym_map->size = 0;
	free(sym_map->kvs);
}

SymValue *sym_map_find(SymMap *sym_map, TokenString *key)
{
	// TODO: Consider a map
	SymKV *kvs = sym_map->kvs;
	for (size_t i = 0; i < sym_map->len; ++i) {
		if (token_string_cmp(&kvs[i].token_string, key) == 0) { return &kvs[i].value; }
	}
	return NULL;
}

void sym_map_insert(SymMap *sym_map, TokenString key, SymValue value)
{
	SymValue *prev_value = sym_map_find(sym_map, &key);
	if (prev_value != NULL) {
		*prev_value = value;
		return;
	}

	sym_map->kvs[sym_map->len++] = (SymKV){
		.token_string = key,
		.value = value,
	};

	if (sym_map->len >= sym_map->size) {
		sym_map->size *= 2;
		sym_map->kvs = realloc(sym_map->kvs, sizeof(SymKV) * sym_map->size);
	}
}

void env_init(Env *env, Arena *arena)
{
	SymMap sym_map = { 0 };
	sym_map_init(&sym_map, arena);
	env->sym_map = sym_map;
	env->arena = arena;
}

void env_destroy(Env *env)
{
	sym_map_destroy(&env->sym_map);
}

SymValue *env_find_ident(Env *env, TokenString *key)
{
	return sym_map_find(&env->sym_map, key);
}

SymValue eval_expr(Env *env, Expr *expr);

void expr_print(Expr *expr);

PostfixToken cook_to_postfix_token(Expr *expr)
{
	switch (expr->kind) {
	case EXPR_NUM: {
		return (PostfixToken){ .kind = POSTFIX_TOKEN_NUM,
				       .data = (PostfixTokenData){
					       .num = expr->data.num,
				       } };
	} break;
	case EXPR_IDENT: {
		return (PostfixToken){ .kind = POSTFIX_TOKEN_VAR,
				       .data = (PostfixTokenData){
					       .var = expr->data.ident.token_string,
				       } };
	} break;
	default: {
		expr_print(expr);
		unreachable();
	} break;
	}
}

PostfixToken cook_operator_to_postfix_token(Operator operator)
{
	return (PostfixToken){ .kind = POSTFIX_TOKEN_OPERATOR,
			       .data =
				       (PostfixTokenData){
					       .operator = operator},
			       };
}

void operator_stack_init(OperatorStack *stack)
{
	stack->size = 4;
	stack->len = 0;
	stack->vec = malloc(sizeof(Operator) * stack->size);
}

Operator *operator_stack_pop(OperatorStack *stack)
{
	if (stack->len == 0) return NULL;
	return &stack->vec[--stack->len];
}

Operator *operator_stack_peak(OperatorStack *stack)
{
	if (stack->len == 0) return NULL;
	return &stack->vec[stack->len - 1];
}

void operator_stack_push(OperatorStack *stack, Operator operator)
{
	stack->vec[stack->len++] = operator;
	if (stack->len >= stack->size) {
		stack->size *= 2;
		stack->vec = realloc(stack->vec, sizeof(Operator) * stack->size);
	}
}

void operator_stack_arena(OperatorStack *stack, Arena *arena)
{
	Operator *arena_vec = arena_alloc(arena, stack->len);
	memcpy(arena_vec, stack->vec, sizeof(Operator) * stack->len);
	free(stack->vec);
	stack->vec = arena_vec;
}

bool operator_stack_is_empty(OperatorStack *stack)
{
	return stack->len == 0;
}

void operator_stack_destroy(OperatorStack *stack)
{
	free(stack->vec);
}

void postfix_push(Postfix *postfix, PostfixToken token)
{
	postfix->tokens[postfix->len++] = token;
	if (postfix->len >= postfix->size) {
		postfix->size *= 2;
		postfix->tokens = realloc(postfix->tokens, sizeof(PostfixToken) * postfix->size);
	}
}

void postfix_arena(Postfix *postfix, Arena *arena)
{
	PostfixToken *postfix_tokens = arena_alloc(arena, sizeof(PostfixToken) * postfix->len);
	memcpy(postfix_tokens, postfix->tokens, sizeof(PostfixToken) * postfix->len);
	free(postfix->tokens);
	postfix->tokens = postfix_tokens;
}

int operator_prec(Operator a)
{
	switch (a) {
	case OPERATOR_PLUS:
	case OPERATOR_MINUS: return 1;
	case OPERATOR_MULT:
	case OPERATOR_DIV: return 2;
	}
}

int operator_cmp(Operator a, Operator b)
{
	return operator_prec(a) - operator_prec(b);
}

void process_infix(Postfix *postfix, OperatorStack *stack, Infix infix);

void process_infix_expr(Postfix *postfix, OperatorStack *stack, Expr *expr_a)
{
	switch (expr_a->kind) {
	case EXPR_PAREN: {
		Expr *paren_expr = expr_a->data.paren.expr;
		if (paren_expr->kind == EXPR_INFIX) {
			process_infix(postfix, stack, paren_expr->data.infix);
		} else if (paren_expr->kind == EXPR_PAREN) {
			process_infix_expr(postfix, stack, paren_expr);
		} else {
			PostfixToken postfix_token = cook_to_postfix_token(paren_expr);
			postfix_push(postfix, postfix_token);
		}
	} break;
	case EXPR_IDENT:
	case EXPR_NUM: {
		PostfixToken postfix_a = cook_to_postfix_token(expr_a);
		postfix_push(postfix, postfix_a);
	} break;
	case EXPR_INFIX: {
		process_infix(postfix, stack, expr_a->data.infix);
	} break;
	default: {
		expr_print(expr_a);
		fprintf(stderr, "%d:Not allowed\n", __LINE__);
		exit(1);
	}
	}
}

void process_operator_stack(Postfix *postfix, OperatorStack *stack, Operator operator)
{
	while (!operator_stack_is_empty(stack) &&
	       operator_cmp(*operator_stack_peak(stack), operator) >= 0) {
		postfix_push(postfix, cook_operator_to_postfix_token(*operator_stack_pop(stack)));
	}
}

bool switch_expr_b(Postfix *postfix, OperatorStack *stack, Infix *infix, Expr *expr_b)
{
	switch (expr_b->kind) {
	case EXPR_INFIX: {
		*infix = expr_b->data.infix;
		Expr *expr_a = infix->expr_a;

		process_infix_expr(postfix, stack, expr_a);
		process_operator_stack(postfix, stack, infix->operator);
	} break;
	case EXPR_PAREN: {
		process_infix_expr(postfix, stack, expr_b->data.paren.expr);
		return false;
	} break;
	case EXPR_IDENT:
	case EXPR_NUM: {
		Expr *expr_b = infix->expr_b;
		PostfixToken postfix_b = cook_to_postfix_token(expr_b);
		postfix_push(postfix, postfix_b);
		return false;
	} break;
	default: {
		expr_print(expr_b);
		unreachable();
	}
	}
	return true;
}

void process_infix(Postfix *postfix, OperatorStack *stack, Infix infix)
{
	process_infix_expr(postfix, stack, infix.expr_a);

	while (true) {
		operator_stack_push(stack, infix.operator);
		Expr *expr_b = infix.expr_b;

		if (!switch_expr_b(postfix, stack, &infix, expr_b)) break;
	}

	for (Operator *operator = operator_stack_pop(stack); operator != NULL;
	     operator = operator_stack_pop(stack)) {
		postfix_push(postfix, cook_operator_to_postfix_token(*operator));
	}
}

SymValue eval_infix(Env *env, Infix infix)
{
	OperatorStack stack = { 0 };
	Postfix postfix = (Postfix){
		.tokens = malloc(sizeof(PostfixToken) * 4),
		.len = 0,
		.size = 4,
	};

	operator_stack_init(&stack);
	process_infix(&postfix, &stack, infix);

	assert(operator_stack_is_empty(&stack));
	operator_stack_destroy(&stack);
	postfix_arena(&postfix, env->arena);

	return (SymValue){ .kind = SYM_VALUE_POSTFIX,
			   .data = (SymValueData){ .postfix = postfix } };
}

SymValue eval_ident(Env *env, Ident ident)
{
	SymValue *sym_map_value = env_find_ident(env, &ident.token_string);

	if (sym_map_value != NULL) {
		return *sym_map_value;
	} else {
		return (SymValue){ .kind = SYM_VALUE_SYM,
			.data = (SymValueData){ .sym = ident.token_string } };
	}
}

SymValue eval_expr(Env *env, Expr *expr)
{
	switch (expr->kind) {
	case EXPR_NUM: {
		return (SymValue){ .kind = SYM_VALUE_NUM,
				   .data = (SymValueData){ .num = expr->data.num } };
	} break;
	case EXPR_IDENT: {
		return eval_ident(env, expr->data.ident);
	} break;
	case EXPR_FUNC: {
		// TODO:
		return (SymValue) { .kind = SYM_VALUE_NIL };
	} break;
	case EXPR_PAREN: {
		return eval_expr(env, expr->data.paren.expr);
	} break;
	case EXPR_INFIX: {
		return eval_infix(env, expr->data.infix);
	} break;
	}
}

void env_assign(Env *env, Ident ident, Expr *expr)
{
	sym_map_insert(&env->sym_map, ident.token_string, eval_expr(env, expr));
}

SymValue eval_str(Env *env, Arena *arena, char *str)
{
	Parser parser = { 0 };
	parser_init(&parser, str, arena);
	while (true) {
		Node node = parser_next(&parser);
		switch (node.kind) {
		case NODE_ASSIGN: {
			Assign *assign = &node.data.assign;
			env_assign(env, assign->name, assign->expr);
		} break;
		case NODE_EXPR: {
			return eval_expr(env, node.data.expr);
		} break;
		case NODE_ASSIGN_FUNC: {
			// TODO
		} break;
		case NODE_EOF: {
			return (SymValue) {
				.kind = SYM_VALUE_NIL,
			};
		} break;
		}
	}
}

void lexer_print(Lexer *lexer)
{
	Token token = lexer_next(lexer);
	while (token.kind != TOKEN_EOF) {
		token_print(&token);
		token = lexer_next(lexer);
	}
}

void lexer_test(void)
{
	/* Lifetime of arena exceeds that of Lexer */
	Arena *arena = arena_create(ARENA_SIZE);
	{
		Lexer lexer = { 0 };
		const char *src = "A + B";
		lexer_init(&lexer, src, arena);

		lexer_print(&lexer);
	}

	{
		Lexer lexer = { 0 };
		const char *src = "1 + 1.3332 == hello()-*/ *   \n p_+= hi_jd";
		lexer_init(&lexer, src, arena);

		lexer_print(&lexer);
	}
	arena_destroy(arena);
}

// Oh my god, this is so hacky, but hilarious
size_t indent_level = 0;

void indent_print(void)
{
	for (size_t i = 0; i < indent_level; ++i) { fputs("    ", stdout); }
}

void operator_print(Operator operator)
{
#define C(x)                                                                                       \
	case x: {                                                                                  \
		printf(#x);                                                                        \
		printf("\n");                                                                      \
	} break;
	indent_print();
	// clang-format off
	switch (operator) {
	C(OPERATOR_PLUS)
	C(OPERATOR_MINUS)
	C(OPERATOR_MULT)
	C(OPERATOR_DIV)
	}
	// clang-format on
}

void expr_print(Expr *expr)
{
#define iprintf(x)                                                                                 \
	indent_print();                                                                            \
	printf(x);
	switch (expr->kind) {
	case EXPR_NUM: {
		indent_print();
		printf("NUM: %lf\n", expr->data.num);
	} break;
	case EXPR_IDENT: {
		indent_print();
		printf("IDENT: ");
		token_string_println(&expr->data.ident.token_string);
	} break;
	case EXPR_FUNC: {
		Func *func = &expr->data.func;
		iprintf("FUNC: {\n");
		++indent_level;
		indent_print();
		printf("NAME: ");
		token_string_println(&func->name.token_string);
		iprintf("ARGS: {\n");
		++indent_level;
		for (size_t i = 0; i < func->args.len; ++i) { expr_print(func->args.exprs[i]); }
		--indent_level;
		iprintf("}\n");
		--indent_level;
		iprintf("}\n");
	} break;
	case EXPR_INFIX: {
		iprintf("INFIX: {\n");
		++indent_level;

		operator_print(expr->data.infix.operator);
		expr_print(expr->data.infix.expr_a);
		expr_print(expr->data.infix.expr_b);

		--indent_level;
		iprintf("}\n");
	} break;
	case EXPR_PAREN: {
		iprintf("PAREN: {\n");
		++indent_level;

		expr_print(expr->data.paren.expr);

		--indent_level;
		iprintf("}\n");
	} break;
	}
#undef iprint
}

void assign_func_print(AssignFunc assign_func)
{
#define iprintf(x)                                                                                 \
	indent_print();                                                                            \
	printf(x);

	iprintf("NAME: ");
	token_string_println(&assign_func.name.token_string);

	iprintf("ARGS: {\n");
	++indent_level;
	for (size_t i = 0; i < assign_func.args.len; ++i) {
		indent_print();
		printf("ARG_NAME: ");
		token_string_println(&assign_func.args.idents[i].token_string);
	}
	--indent_level;
	iprintf("}\n");

	iprintf("EXPR: {\n");

	++indent_level;
	expr_print(assign_func.expr);
	--indent_level;
	iprintf("}\n");

#undef iprint
}

void node_print(Node *node)
{
	switch (node->kind) {
	case NODE_ASSIGN: {
	} break;
	case NODE_ASSIGN_FUNC: {
		assign_func_print(node->data.assign_func);
	} break;
	case NODE_EXPR: {
		expr_print(node->data.expr);
	} break;
	case NODE_EOF: {
		printf("EOF\n");
	}
	}
}

void parser_test(void)
{
	Arena *arena = arena_create(ARENA_SIZE);
	printf("size %lu\n", arena->size);

	{
		Parser parser = { 0 };
		const char *src = "A + B";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}

	{
		Parser parser = { 0 };
		const char *src = "A + B * C - D";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		//printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}

#if 1
	{
		Parser parser = { 0 };
		const char *src = "1 + 1 + 1 - 1";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		//node_print(&node);
		arena_clear(arena);
	}

	{
		Parser parser = { 0 };
		const char *src = "f(x) = x + 1";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}

	{
		Parser parser = { 0 };
		const char *src = "x + f(x)";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}

	{
		Parser parser = { 0 };
		const char *src = "f(x + 1)";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}

	{
		Parser parser = { 0 };
		const char *src = "(A + B) * C";

		parser_init(&parser, src, arena);

		Node node = parser_next(&parser);
		printf("index %lu\n", parser.arena->index);
		node_print(&node);
		arena_clear(arena);
	}
#endif

	arena_destroy(arena);
}

void lexer_repl(void)
{
	char input_buf[INPUT_BUF_SIZE] = { 0 };
	Arena *arena = arena_create(ARENA_SIZE);

	while (1) {
		fputs("*> ", stdout);
		if (!fgets(input_buf, INPUT_BUF_SIZE, stdin)) { break; }
		Lexer lexer = { 0 };
		lexer_init(&lexer, input_buf, arena);

		lexer_print(&lexer);
		arena_clear(arena);
	}
}

void parser_repl(void)
{
	char input_buf[INPUT_BUF_SIZE] = { 0 };
	Arena *arena = arena_create(ARENA_SIZE);

	while (1) {
		fputs("*> ", stdout);
		if (!fgets(input_buf, INPUT_BUF_SIZE, stdin)) { break; }
		Parser parser = { 0 };
		parser_init(&parser, input_buf, arena);

		Node node = parser_next(&parser);
		if (!parser.error) { node_print(&node); }
		arena_clear(arena);
	}
	arena_destroy(arena);
}

void postfix_print(Postfix postfix)
{
	for (size_t i = 0; i < postfix.len; ++i) {
		PostfixToken *token = &postfix.tokens[i];
		switch (token->kind) {
		case POSTFIX_TOKEN_OPERATOR: {
			operator_print(token->data.operator);
		} break;
		case POSTFIX_TOKEN_NUM: {
			printf("NUM: %lf\n", token->data.num);
		} break;
		case POSTFIX_TOKEN_VAR: {
			printf("VAR: ");
			token_string_println(&token->data.var);
		} break;
		}
	}
}

double eval_operator(Operator operator, double a, double b)
{
	switch (operator) {
	case OPERATOR_PLUS: {
		return a + b;
	} break;
	case OPERATOR_MINUS: {
		return a - b;
	} break;
	case OPERATOR_MULT: {
		return a * b;
	} break;
	case OPERATOR_DIV: {
		return a / b;
	} break;
	}
}

void postfix_eval_print(Env *env, Postfix postfix)
{
	size_t size = 4;
	size_t len = 0;
	double *stack = malloc(sizeof(double) * size);
	char string[READ_BUF_SIZE] = { 0 };
	PostfixToken *tokens = postfix.tokens;

	for (size_t i = 0; i < postfix.len; ++i) {
		PostfixToken *token = &tokens[i];
		switch (token->kind) {
		case POSTFIX_TOKEN_OPERATOR: {
			assert(len >= 2);
			double evaluated =
				eval_operator(token->data.operator, stack[len - 2], stack[len - 1]);
			stack[len - 2] = evaluated;
			--len;
		} break;
		case POSTFIX_TOKEN_NUM: {
			stack[len++] = token->data.num;
			if (len >= size) {
				size *= 2;
				stack = realloc(stack, sizeof(double) * size);
			}
		} break;
		case POSTFIX_TOKEN_VAR: {
			SymValue *sym_value = env_find_ident(env, &token->data.var);

			if (sym_value == NULL) {
				fprintf(stdout, "Unbounded variable:'");
				token_string_print(&token->data.var);
				fputs( "'\n", stdout);
				return;
			}
			if (sym_value->kind != SYM_VALUE_NUM) {
				fprintf(stderr, "%s:%d:Unimplemented", __FILE__, __LINE__);
				token_string_println(&token->data.var);
				return;
			}
			double num = sym_value->data.num;

			stack[len++] = num;
			if (len >= size) {
				size *= 2;
				stack = realloc(stack, sizeof(double) * size);
			}
		} break;
		}
	}

	printf("%lf\n", stack[len - 1]);
	free(stack);
}

void sym_value_print(Env *env, SymValue sym_value)
{
	switch (sym_value.kind) {
	case SYM_VALUE_POSTFIX: {
		//postfix_print(sym_value.data.postfix);
		postfix_eval_print(env, sym_value.data.postfix);
	} break;
	case SYM_VALUE_NUM: {
		printf("%lf\n", sym_value.data.num);
	} break;
	case SYM_VALUE_SYM: {
		SymValue *sym_value_var = env_find_ident(env, &sym_value.data.sym);
		if (sym_value_var == NULL) {
			token_string_println(&sym_value.data.sym);
		} else {
			sym_value_print(env, *sym_value_var);
		}
	} break;
	case SYM_VALUE_NIL: break;
	}
}

void repl(void)
{
	char input_buf[INPUT_BUF_SIZE] = { 0 };
	Arena *arena = arena_create(ARENA_SIZE);
	Env env = { 0 };
	env_init(&env, arena);

	while (1) {
		fputs("*> ", stdout);
		if (!fgets(input_buf, INPUT_BUF_SIZE, stdin)) { break; }

		sym_value_print(&env, eval_str(&env, arena, input_buf));
	}

	printf("%lu\n", arena->index);
	env_destroy(&env);
	arena_destroy(arena);
}

void string_test(void)
{
	TokenString a = (TokenString){ .str = "Hello world", .len = 11 };
	TokenString b = (TokenString){ .str = "ABC", .len = 3 };
	assert(token_string_cmp(&a, &a) == 0);
	assert(token_string_cmp(&a, &b) > 0);
	assert(token_string_cmp(&b, &a) < 0);
}

void operator_prec_test(void)
{
	Operator a = OPERATOR_MINUS;
	Operator b = OPERATOR_MULT;
	Operator c = OPERATOR_PLUS;

	assert(operator_cmp(a, b) < 0);
	assert(operator_cmp(b, a) > 0);
	assert(operator_cmp(a, c) == 0);
}

void eval_test(void)
{
	Arena *arena = arena_create(ARENA_SIZE);

	{
		Env env = { 0 };
		env_init(&env, arena);
		SymValue value = eval_str(&env, arena, "69 + 420");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		SymValue value = eval_str(&env, arena, "69 + 420 - 10");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		SymValue value = eval_str(&env, arena, "(4 / 4) * ((3) * 2)");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		SymValue value = eval_str(&env, arena, "(1 + 1) * (2 * (2 - 1)) + 5");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		SymValue value = eval_str(&env, arena, "(1 - 1)");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		eval_str(&env, arena, "A = 10");
		eval_str(&env, arena, "B = 11");
		eval_str(&env, arena, "C = 12");
		eval_str(&env, arena, "D = 13");
		SymValue value = eval_str(&env, arena, "A + B * C - D");
		sym_value_print(&env, value);
	}

	{
		Env env = { 0 };
		env_init(&env, arena);
		eval_str(&env, arena, "A = 10");
		eval_str(&env, arena, "B = 11");
		eval_str(&env, arena, "C = 12");
		eval_str(&env, arena, "D = 13");
		SymValue value = eval_str(&env, arena, "(A + B) * C - D");
		sym_value_print(&env, value);
	}
}

int main(void)
{
	//string_test();

	//lexer_test();
	//lexer_repl();

	//parser_test();
	//parser_repl();

	//eval_test();
	repl();
	return 0;
}
