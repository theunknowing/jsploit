/**
 * HTML Parser
 *
 * Native HTML parsing utilities for exploit development. No external dependencies; uses
 * regex-based extraction. Suitable for well-formed or typical server-rendered HTML. For
 * malformed or complex DOM, consider that regex does not implement full HTML5 parsing.
 *
 * Features: CSRF token extraction, form parsing, link/input/meta/script extraction.
 */

import { ParseError } from '../utils/errors.js';

/**
 * Common CSRF token field names
 */
const CSRF_FIELD_NAMES = [
    'csrf',
    'csrf_token',
    'csrftoken',
    '_csrf',
    '_token',
    'token',
    'authenticity_token',
    '__RequestVerificationToken',
    '_csrf_token',
    'csrfmiddlewaretoken',
    'antiforgery',
    '__VIEWSTATE',
    '__EVENTVALIDATION',
];

/**
 * HTML Document wrapper for parsing
 */
export class HTMLDocument {
    /**
     * Create HTML document from string
     * @param {string} html - HTML content
     */
    constructor(html) {
        this.html = html || '';
        this._forms = null;
        this._links = null;
        this._inputs = null;
        this._scripts = null;
        this._metas = null;
    }

    /**
     * Get page title
     * @returns {string|null}
     */
    get title() {
        const match = this.html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        return match ? this._decodeEntities(match[1].trim()) : null;
    }

    /**
     * Find CSRF token in the document
     * @param {string[]} fieldNames - Custom field names to search
     * @returns {object|null} - { name, value } or null
     */
    findCSRFToken(fieldNames = []) {
        const searchNames = [...CSRF_FIELD_NAMES, ...fieldNames];

        // Search in hidden inputs
        for (const name of searchNames) {
            // Case-insensitive search
            const patterns = [
                new RegExp(`<input[^>]*name=["']${name}["'][^>]*value=["']([^"']+)["']`, 'i'),
                new RegExp(`<input[^>]*value=["']([^"']+)["'][^>]*name=["']${name}["']`, 'i'),
            ];

            for (const pattern of patterns) {
                const match = this.html.match(pattern);
                if (match) {
                    return { name, value: match[1] };
                }
            }
        }

        // Search in meta tags
        for (const name of searchNames) {
            const patterns = [
                new RegExp(`<meta[^>]*name=["']${name}["'][^>]*content=["']([^"']+)["']`, 'i'),
                new RegExp(`<meta[^>]*content=["']([^"']+)["'][^>]*name=["']${name}["']`, 'i'),
            ];

            for (const pattern of patterns) {
                const match = this.html.match(pattern);
                if (match) {
                    return { name, value: match[1] };
                }
            }
        }

        // Search in data attributes
        const dataPattern = /data-csrf(?:-token)?=["']([^"']+)["']/i;
        const dataMatch = this.html.match(dataPattern);
        if (dataMatch) {
            return { name: 'data-csrf', value: dataMatch[1] };
        }

        return null;
    }

    /**
     * Get all forms in the document
     * @returns {FormElement[]}
     */
    get forms() {
        if (this._forms !== null) return this._forms;

        this._forms = [];
        const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
        let match;

        while ((match = formRegex.exec(this.html)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            const content = match[2];

            this._forms.push(new FormElement({
                action: attrs.action || '',
                method: (attrs.method || 'GET').toUpperCase(),
                id: attrs.id || '',
                name: attrs.name || '',
                enctype: attrs.enctype || '',
                content,
            }));
        }

        return this._forms;
    }

    /**
     * Find form by action, id, or name
     * @param {string} selector - Action URL, id, or name
     * @returns {FormElement|null}
     */
    findForm(selector) {
        for (const form of this.forms) {
            if (form.action.includes(selector) ||
                form.id === selector ||
                form.name === selector) {
                return form;
            }
        }
        return null;
    }

    /**
     * Get form by index
     * @param {number} index - Form index
     * @returns {FormElement|null}
     */
    getForm(index = 0) {
        return this.forms[index] || null;
    }

    /**
     * Get all links in the document
     * @returns {object[]}
     */
    get links() {
        if (this._links !== null) return this._links;

        this._links = [];
        const linkRegex = /<a([^>]*)>/gi;
        let match;

        while ((match = linkRegex.exec(this.html)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            if (attrs.href) {
                this._links.push({
                    href: attrs.href,
                    text: this._extractLinkText(this.html, match.index),
                    id: attrs.id || '',
                    class: attrs.class || '',
                    target: attrs.target || '',
                    rel: attrs.rel || '',
                });
            }
        }

        return this._links;
    }

    /**
     * Find links matching a pattern
     * @param {string|RegExp} pattern - Pattern to match href or text
     * @returns {object[]}
     */
    findLinks(pattern) {
        const regex = pattern instanceof RegExp ? pattern : new RegExp(pattern, 'i');
        return this.links.filter(link =>
            regex.test(link.href) || regex.test(link.text)
        );
    }

    /**
     * Get all inputs in the document
     * @returns {object[]}
     */
    get inputs() {
        if (this._inputs !== null) return this._inputs;

        this._inputs = [];
        const inputRegex = /<input([^>]*)>/gi;
        let match;

        while ((match = inputRegex.exec(this.html)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            this._inputs.push({
                type: attrs.type || 'text',
                name: attrs.name || '',
                value: attrs.value || '',
                id: attrs.id || '',
                class: attrs.class || '',
                placeholder: attrs.placeholder || '',
                required: 'required' in attrs,
                disabled: 'disabled' in attrs,
                readonly: 'readonly' in attrs,
            });
        }

        return this._inputs;
    }

    /**
     * Find input by name or id
     * @param {string} nameOrId - Input name or id
     * @returns {object|null}
     */
    findInput(nameOrId) {
        return this.inputs.find(input =>
            input.name === nameOrId || input.id === nameOrId
        ) || null;
    }

    /**
     * Get all meta tags
     * @returns {object[]}
     */
    get metas() {
        if (this._metas !== null) return this._metas;

        this._metas = [];
        const metaRegex = /<meta([^>]*)>/gi;
        let match;

        while ((match = metaRegex.exec(this.html)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            this._metas.push(attrs);
        }

        return this._metas;
    }

    /**
     * Get meta tag content by name
     * @param {string} name - Meta name or property
     * @returns {string|null}
     */
    getMeta(name) {
        const meta = this.metas.find(m =>
            m.name === name || m.property === name
        );
        return meta ? meta.content : null;
    }

    /**
     * Get all script tags
     * @returns {object[]}
     */
    get scripts() {
        if (this._scripts !== null) return this._scripts;

        this._scripts = [];
        const scriptRegex = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
        let match;

        while ((match = scriptRegex.exec(this.html)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            this._scripts.push({
                src: attrs.src || '',
                type: attrs.type || '',
                nonce: attrs.nonce || '',
                content: match[2].trim(),
                async: 'async' in attrs,
                defer: 'defer' in attrs,
            });
        }

        return this._scripts;
    }

    /**
     * Find script by src pattern
     * @param {string|RegExp} pattern - Pattern to match src
     * @returns {object|null}
     */
    findScript(pattern) {
        const regex = pattern instanceof RegExp ? pattern : new RegExp(pattern, 'i');
        return this.scripts.find(script => regex.test(script.src)) || null;
    }

    /**
     * Extract text content between tags
     * @param {string} selector - Tag name or simple selector
     * @returns {string[]}
     */
    getText(selector) {
        const regex = new RegExp(`<${selector}[^>]*>([\\s\\S]*?)<\\/${selector}>`, 'gi');
        const results = [];
        let match;

        while ((match = regex.exec(this.html)) !== null) {
            const text = this._stripTags(match[1]).trim();
            if (text) results.push(text);
        }

        return results;
    }

    /**
     * Find elements by attribute value
     * @param {string} attr - Attribute name
     * @param {string} value - Attribute value (partial match)
     * @returns {string[]} - Array of outer HTML
     */
    findByAttribute(attr, value) {
        const regex = new RegExp(`<[^>]*${attr}=["'][^"']*${value}[^"']*["'][^>]*>`, 'gi');
        const matches = this.html.match(regex);
        return matches || [];
    }

    /**
     * Find elements by class name
     * @param {string} className - Class name
     * @returns {string[]}
     */
    findByClass(className) {
        return this.findByAttribute('class', className);
    }

    /**
     * Find element by id
     * @param {string} id - Element id
     * @returns {string|null}
     */
    findById(id) {
        const results = this.findByAttribute('id', id);
        return results.length > 0 ? results[0] : null;
    }

    /**
     * Extract JSON from script tags
     * @param {string} varName - JavaScript variable name
     * @returns {object|null}
     */
    extractJSON(varName) {
        // Try different patterns
        const patterns = [
            new RegExp(`${varName}\\s*=\\s*(\\{[\\s\\S]*?\\});`, 'i'),
            new RegExp(`${varName}\\s*=\\s*(\\[[\\s\\S]*?\\]);`, 'i'),
            new RegExp(`${varName}['"]\\s*:\\s*(\\{[\\s\\S]*?\\})`, 'i'),
        ];

        for (const pattern of patterns) {
            const match = this.html.match(pattern);
            if (match) {
                try {
                    return JSON.parse(match[1]);
                } catch (e) {
                    // Continue to next pattern
                }
            }
        }

        return null;
    }

    /**
     * Parse HTML attributes from string
     * @param {string} attrString - Attribute string
     * @returns {Object}
     * @private
     */
    _parseAttributes(attrString) {
        const attrs = {};
        const regex = /(\w+)(?:=["']([^"']*)["']|=(\S+))?/g;
        let match;

        while ((match = regex.exec(attrString)) !== null) {
            const name = match[1].toLowerCase();
            const value = match[2] || match[3] || '';
            attrs[name] = this._decodeEntities(value);
        }

        return attrs;
    }

    /**
     * Decode HTML entities
     * @param {string} str - String with entities
     * @returns {string}
     * @private
     */
    _decodeEntities(str) {
        const entities = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#39;': "'",
            '&apos;': "'",
            '&#x27;': "'",
            '&#x2F;': '/',
            '&nbsp;': ' ',
        };

        return str.replace(/&[#\w]+;/g, entity => entities[entity] || entity);
    }

    /**
     * Strip HTML tags from string
     * @param {string} str - String with tags
     * @returns {string}
     * @private
     */
    _stripTags(str) {
        return str.replace(/<[^>]*>/g, '').trim();
    }

    /**
     * Extract link text from HTML at position
     * @param {string} html - Full HTML
     * @param {number} startIndex - Start index of <a> tag
     * @returns {string}
     * @private
     */
    _extractLinkText(html, startIndex) {
        const closeTag = html.indexOf('</a>', startIndex);
        if (closeTag === -1) return '';

        const openTagEnd = html.indexOf('>', startIndex);
        if (openTagEnd === -1) return '';

        const content = html.substring(openTagEnd + 1, closeTag);
        return this._stripTags(content).trim();
    }
}

/**
 * Form element wrapper
 */
export class FormElement {
    /**
     * Create form element
     * @param {object} options - Form options
     */
    constructor(options) {
        this.action = options.action || '';
        this.method = options.method || 'GET';
        this.id = options.id || '';
        this.name = options.name || '';
        this.enctype = options.enctype || '';
        this._content = options.content || '';
        this._inputs = null;
        this._selects = null;
        this._textareas = null;
    }

    /**
     * Get all input fields in the form
     * @returns {object[]}
     */
    get inputs() {
        if (this._inputs !== null) return this._inputs;

        this._inputs = [];
        const inputRegex = /<input([^>]*)>/gi;
        let match;

        while ((match = inputRegex.exec(this._content)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            this._inputs.push({
                type: attrs.type || 'text',
                name: attrs.name || '',
                value: attrs.value || '',
                id: attrs.id || '',
            });
        }

        return this._inputs;
    }

    /**
     * Get all select fields in the form
     * @returns {object[]}
     */
    get selects() {
        if (this._selects !== null) return this._selects;

        this._selects = [];
        const selectRegex = /<select([^>]*)>([\s\S]*?)<\/select>/gi;
        let match;

        while ((match = selectRegex.exec(this._content)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            const options = this._parseSelectOptions(match[2]);

            this._selects.push({
                name: attrs.name || '',
                id: attrs.id || '',
                options,
                selectedValue: options.find(o => o.selected)?.value || '',
            });
        }

        return this._selects;
    }

    /**
     * Get all textarea fields in the form
     * @returns {object[]}
     */
    get textareas() {
        if (this._textareas !== null) return this._textareas;

        this._textareas = [];
        const textareaRegex = /<textarea([^>]*)>([\s\S]*?)<\/textarea>/gi;
        let match;

        while ((match = textareaRegex.exec(this._content)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            this._textareas.push({
                name: attrs.name || '',
                id: attrs.id || '',
                value: match[2].trim(),
            });
        }

        return this._textareas;
    }

    /**
     * Get form data as object
     * @returns {Object}
     */
    getData() {
        const data = {};

        // Add inputs
        for (const input of this.inputs) {
            if (input.name && input.type !== 'submit' && input.type !== 'button') {
                if (input.type === 'checkbox' || input.type === 'radio') {
                    // Only include if checked
                    if (input.value) {
                        data[input.name] = input.value;
                    }
                } else {
                    data[input.name] = input.value;
                }
            }
        }

        // Add selects
        for (const select of this.selects) {
            if (select.name) {
                data[select.name] = select.selectedValue;
            }
        }

        // Add textareas
        for (const textarea of this.textareas) {
            if (textarea.name) {
                data[textarea.name] = textarea.value;
            }
        }

        return data;
    }

    /**
     * Find input by name
     * @param {string} name - Input name
     * @returns {object|null}
     */
    getInput(name) {
        return this.inputs.find(i => i.name === name) || null;
    }

    /**
     * Parse attributes from string
     * @param {string} attrString - Attribute string
     * @returns {Object}
     * @private
     */
    _parseAttributes(attrString) {
        const attrs = {};
        const regex = /(\w+)(?:=["']([^"']*)["']|=(\S+))?/g;
        let match;

        while ((match = regex.exec(attrString)) !== null) {
            const name = match[1].toLowerCase();
            const value = match[2] || match[3] || '';
            attrs[name] = value;
        }

        return attrs;
    }

    /**
     * Parse select options
     * @param {string} content - Select inner HTML
     * @returns {object[]}
     * @private
     */
    _parseSelectOptions(content) {
        const options = [];
        const optionRegex = /<option([^>]*)>([^<]*)<\/option>/gi;
        let match;

        while ((match = optionRegex.exec(content)) !== null) {
            const attrs = this._parseAttributes(match[1]);
            options.push({
                value: attrs.value || match[2].trim(),
                text: match[2].trim(),
                selected: 'selected' in attrs,
            });
        }

        return options;
    }
}

/**
 * Parse HTML string into document
 * @param {string} html - HTML content
 * @returns {HTMLDocument}
 */
export function parse(html) {
    return new HTMLDocument(html);
}

/**
 * Quick CSRF token extraction
 * @param {string} html - HTML content
 * @returns {object|null} - { name, value } or null
 */
export function findCSRFToken(html) {
    return new HTMLDocument(html).findCSRFToken();
}

/**
 * Quick form extraction
 * @param {string} html - HTML content
 * @param {string|number} selector - Form selector or index
 * @returns {FormElement|null}
 */
export function findForm(html, selector = 0) {
    const doc = new HTMLDocument(html);
    if (typeof selector === 'number') {
        return doc.getForm(selector);
    }
    return doc.findForm(selector);
}

