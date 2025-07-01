const {EmbedBuilder} = require('discord.js');

module.exports = class EmbedManager extends EmbedBuilder {
  message = null;
  title = null;
  description = null;
  fields = null;

  setTitle(title) {
    this.title = title;
    super.setTitle(title);
    return this;
  }

  setDescription(description) {
    this.description = description;
    super.setDescription(description);
    return this;
  }

  addTitle(title) {
    this.title += "\n" + (title ? title : "");
    super.setTitle(this.title);
    return this;
  }

  addDescription(description) {
    this.description += "\n" + (description ? description : "");
    super.setDescription(this.description);
    return this;
  }

  addFields(...fields) {
    if (!this.fields) this.fields = [];
    this.fields.push(fields);
    super.addFields(fields);
    return this;
  }

  changeField(name, value, inline, new_name) {
    if (!this.fields) {
      return this;
    }
    this.fields.forEach((field, x) => {
      field.forEach((field, y) => {
        if (this.fields[x][y].name === name) {
          this.fields[x][y].name = new_name ? new_name : name;
          this.fields[x][y].value = value;
          if (inline !== undefined)
            this.fields[x][y].inline = !!inline;
        }
      });
    });
    this.fields.forEach((field, i) => {
      if (i === 0)
        super.setFields(field);
      else
        super.addFields(field);
    });
    return this;
  }

  setMessage(message) {
    this.message = message;
    return this;
  }

  async edit() {
    if (this.message)
      await this.message.edit({embeds: [this]});
    return this;
  }
}