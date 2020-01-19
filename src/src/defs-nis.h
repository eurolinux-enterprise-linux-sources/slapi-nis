/*
 * Copyright 2008 Red Hat, Inc.
 *
 * This Program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this Program; if not, write to the
 *
 *   Free Software Foundation, Inc.
 *   59 Temple Place, Suite 330
 *   Boston, MA 02111-1307 USA
 *
 */

#ifndef defaults_h
#define defaults_h
void defaults_get_map_config(const char *mapname,
			     bool_t *secure,
			     const char **filter,
			     const char **key_format,
			     const char **keys_format,
			     const char **value_format,
			     const char **values_format,
			     const char **disallowed_chars);
#endif
