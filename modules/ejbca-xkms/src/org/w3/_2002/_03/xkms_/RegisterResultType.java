
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RegisterResultType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RegisterResultType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}ResultType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}KeyBinding" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}PrivateKey" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RegisterResultType", propOrder = {
    "keyBinding",
    "privateKey"
})
public class RegisterResultType
    extends ResultType
{

    @XmlElement(name = "KeyBinding")
    protected List<KeyBindingType> keyBinding;
    @XmlElement(name = "PrivateKey")
    protected PrivateKeyType privateKey;

    /**
     * Gets the value of the keyBinding property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the keyBinding property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getKeyBinding().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link KeyBindingType }
     * 
     * 
     */
    public List<KeyBindingType> getKeyBinding() {
        if (keyBinding == null) {
            keyBinding = new ArrayList<KeyBindingType>();
        }
        return this.keyBinding;
    }

    /**
     * Gets the value of the privateKey property.
     * 
     * @return
     *     possible object is
     *     {@link PrivateKeyType }
     *     
     */
    public PrivateKeyType getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the value of the privateKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link PrivateKeyType }
     *     
     */
    public void setPrivateKey(PrivateKeyType value) {
        this.privateKey = value;
    }

}