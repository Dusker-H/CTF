const crypto = require('crypto')
const { Sequelize, DataTypes } = require('sequelize')
const fs = require('fs')
const { join } = require('path')

class Database {
    async init(callback) {
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: './dB.sqlite',
            logging: false
        })

        await this.sequelize.authenticate()

        this.Users = this.sequelize.define('User', {
            uuid: {
                type: DataTypes.UUID,
                defaultValue: DataTypes.UUIDV4,
                allowNull: false,
                unique: true
            },
            username: {
                type: DataTypes.STRING,
                allowNull: false,
                unique: true
            },
            password: {
                type: DataTypes.STRING,
                allowNull: false,
                set(value){
                    this.setDataValue('password', crypto.createHash('sha256').update(value).digest('hex'))
                }
            }
        })
        this.Images = this.sequelize.define('Image', {
            fileName: {
                type: DataTypes.STRING
            }
        })

        this.Users.hasMany(this.Images, {
            allowNull: false
        })
        this.Images.belongsTo(this.Users,  { onDelete: 'CASCADE' })

        await this.sequelize.sync()

        this.admin = (await this.Users.findOrCreate({
            where: {
                uuid: process.env.ADMIN_UUID
            },
            defaults: {
                username: 'admin',
                password: crypto.randomBytes(13).toString('hex')
            }
        }))[0]
        let adminImages = await new Promise((resolve, reject) => {
            fs.readdir(join(__dirname, 'uploads'), (err, files) => {
                if (err) return reject()
                resolve(files.map((file) => {
                    if (
                        file.startsWith(`${this.admin.username}-${this.admin.uuid}`)
                    ) {
                        return {
                            UserId: this.admin.id,
                            fileName: file
                        }
                    }
                }))
            })
        })
        console.log(adminImages)
        if (!await this.Images.count()) {
            await this.Images.bulkCreate(adminImages)
        }
        this.admin.images = JSON.parse(JSON.stringify(await this.admin.getImages()))
        console.log(this.admin.toJSON())
        callback.bind(this)()
    }

    async registerUser(user) {
        return await this.Users.create(user)
    }

    async loginUser(username, password) {
        const user = await this.Users.findOne({
            where: { username }
        })
        if (!user || crypto.createHash('sha256').update(password).digest('hex') !== user.password) {
            return false
        }
        return user
    }

    async getUser(uuid) {
        return await this.Users.findOne({
            where: { uuid }
        })
    }

    async getImagesCount(uuid) {
        return await this.Images.count({
            where: {
                UserId: (await this.getUser(uuid)).id
            }
        })
    }

    async getImages(uuid) {
        return JSON.parse(JSON.stringify(await this.Images.findAll({
            where: {
                UserId: (await this.getUser(uuid)).id
            }
        })))
    }
}

module.exports = Database
